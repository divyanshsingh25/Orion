from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import UTC, datetime, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.session import AsyncSessionLocal
from app.middleware.websocket_manager import connection_manager
from app.models import AIAnalysis, Finding, Scan, Target, User
from app.scanner import OrionScanner
from app.schemas.scan import ScanCreateRequest, ScanRead
from app.services.ai_service import AIService
from app.services.ai_verifier import AIVerifier
from app.services.report_service import ReportService
from app.services.target_service import TargetService

logger = logging.getLogger("orion.scan")

_active_scan_tasks: dict[str, asyncio.Task] = {}
_live_telemetry_cache: dict[str, dict[str, Any]] = {}


def _normalize_mod_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _build_initial_modules(scan_type: str | None) -> dict[str, dict[str, Any]]:
    is_quick = (scan_type or "").lower() in ("quick", "quick scan", "fast")
    module_names = [
        "Target Initialization",
        "DNS Enumeration",
        "WHOIS & Network Intel",
    ]
    if not is_quick:
        module_names.extend([
            "Port Scanner",
            "Service Fingerprinting",
            "OS Fingerprinting",
        ])
    module_names.append("Web & SPA Crawler")
    if not is_quick:
        module_names.append("Playwright Deep Discovery")
    module_names.extend([
        "TLS / SSL Analysis",
        "Cookie & JWT Security",
        "Security Headers",
        "CORS Scanner",
        "CSRF Scanner",
        "XSS Injection",
    ])
    if not is_quick:
        module_names.extend([
            "SQL Injection",
            "SSRF Scanner",
            "LFI / File Inclusion",
            "XXE Injection",
            "Remote Code Exec",
            "IDOR / Access Control",
        ])
    module_names.append("Open Redirect")
    if not is_quick:
        module_names.extend([
            "Path Traversal",
            "NoSQL Injection",
            "LDAP Injection",
            "SSTI Template Injection",
            "API & GraphQL Security",
        ])
    module_names.append("Risk Scoring & Report")

    modules_dict = {}
    for idx, name in enumerate(module_names):
        key = _normalize_mod_key(name)
        modules_dict[key] = {
            "name": name,
            "status": "Scanning" if idx == 0 else "Queued",
            "progress": 1 if idx == 0 else 0,
            "findings": 0,
            "order": idx,
        }
    return modules_dict


def _get_telemetry_bucket(scan_id: str) -> dict[str, Any]:
    if scan_id not in _live_telemetry_cache:
        _live_telemetry_cache[scan_id] = {
            "events": [],
            "modules": {},
            "eta_seconds": 0,
            "target_url": "",
            "report_id": None,
        }
    return _live_telemetry_cache[scan_id]


def safe_duration(started_at: datetime | None, completed_at: datetime | None) -> float:
    """
    Safely calculates the duration between two datetimes in seconds.
    Converts offset-naive datetimes to UTC-aware to avoid TypeError.
    Returns 0.0 if either datetime is None.
    """
    if started_at is None or completed_at is None:
        return 0.0

    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)

    if completed_at.tzinfo is None:
        completed_at = completed_at.replace(tzinfo=timezone.utc)

    return max(0.0, (completed_at - started_at).total_seconds())

class ScanService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.settings = get_settings()
        self.target_service = TargetService(db)
        self.ai_service = AIService()
        self.ai_verifier = AIVerifier(self.settings)
        self.report_service = ReportService(db)
        self.scanner = OrionScanner()
        self._progress_lock = asyncio.Lock()
        self._last_db_commit = 0.0

    async def create_scan(self, user: User, payload: ScanCreateRequest) -> ScanRead:
        target = await self.target_service.get_target(user, payload.target_id)
        scan = Scan(
            project_id=target.project_id,
            target_id=target.id,
            user_id=user.id,
            scan_type=payload.scan_type,
            depth=payload.depth,
            auth_config_json=payload.auth_config,
            status="queued",
            progress_percent=0,
            total_findings=0,
        )
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)

        # Fire-and-forget: the background task gets its OWN db session
        # so we don't hold the request-scoped session open.
        scan_id = scan.id
        if getattr(self.settings, "use_celery", False):
            from app.workers.tasks import execute_scan_task
            execute_scan_task.delay(scan_id)
        else:
            task = asyncio.create_task(self._run_scan_background(scan_id))
            _active_scan_tasks[scan_id] = task
            task.add_done_callback(lambda _: _active_scan_tasks.pop(scan_id, None))

        from app.schemas.scan import ScanRead
        return ScanRead.model_validate(scan, from_attributes=True)

    async def _run_scan_background(self, scan_id: str) -> None:
        """Wrapper that creates an independent DB session for the background scan."""
        try:
            from app.database.session import AsyncSessionLocal
            async with AsyncSessionLocal() as db:
                bg_service = ScanService(db)
                await bg_service.run_scan(scan_id)
        except asyncio.CancelledError:
            logger.info("Background scan %s cancelled", scan_id)
        except Exception:
            logger.exception("Background scan %s failed", scan_id)

    async def run_scan(self, scan_id: str) -> Scan:
        result = await self.db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

        target_result = await self.db.execute(select(Target).where(Target.id == scan.target_id))
        target = target_result.scalar_one()
        user_result = await self.db.execute(select(User).where(User.id == scan.user_id))
        user = user_result.scalar_one()

        scan.status = "running"
        scan.started_at = datetime.now(UTC)
        scan.progress_percent = 1
        await self.db.commit()

        # Initialize live telemetry buffer with full module roster for reconnecting clients
        bucket = _get_telemetry_bucket(scan.id)
        bucket["target_url"] = target.url
        init_event = {
            "time": datetime.now(UTC).strftime("%H:%M:%S"),
            "level": "SCAN",
            "message": f"Scan initialized for {target.url}",
        }
        bucket["events"] = [init_event]
        bucket["modules"] = _build_initial_modules(scan.scan_type)

        await connection_manager.broadcast(scan.id, {
            "event": "scan_started",
            "scan_id": scan.id,
            "progress": 1,
            "current_module": "Initialization",
            "current_url": target.url,
            "requests_count": 0,
            "endpoints_count": 0,
            "findings_count": 0,
            "open_ports": 0,
            "services_count": 0,
            "eta_seconds": 0,
            "log": init_event,
            "module_info": {"name": "Target Initialization", "status": "Scanning", "findings": 0},
        })

        async def progress_callback(payload: dict[str, Any]) -> None:
            await self._update_scan_progress(scan, payload)
            try:
                await connection_manager.broadcast(scan.id, payload)
            except Exception:
                pass
        logger.info(
            "[SCAN_START] scan_id=%s target=%s scan_type=%s execution_mode=%s",
            scan.id,
            target.url,
            scan.scan_type,
            "celery" if getattr(self.settings, "use_celery", False) else "asyncio_task",
        )
        logger.info(
            "[SCANNER_INIT] scan_id=%s adapter=%s modules_count=%d",
            scan.id,
            self.scanner.__class__.__name__,
            len(getattr(self.scanner, "scanner_types", {})),
        )

        try:
            logger.info("[TARGET_REQUEST_START] scan_id=%s target=%s", scan.id, target.url)
            assessment = await self.scanner.scan(
                target.url,
                scan.scan_type,
                scan.depth,
                progress=progress_callback,
                auth_config=scan.auth_config_json,
            )
            created_findings = await self._persist_findings(scan, assessment["findings"])
            scan.total_findings = len(created_findings)
            logger.info("[SCAN_PERSIST] scan_id=%s findings_persisted=%d", scan.id, len(created_findings))
            scan.statistics_json = assessment["statistics"]
            scan.summary_json = {"recon": assessment["recon"], "ai_context": assessment["ai_context"]}
            scan.status = "completed"
            scan.progress_percent = 100
            scan.current_module = "Complete"
            scan.current_url = target.url
            scan.completed_at = datetime.now(UTC)
            scan.duration_seconds = assessment["duration_seconds"]
            logger.info("[SCAN_COMPLETE] scan_id=%s duration=%.2fs total_findings=%d", scan.id, scan.duration_seconds or 0.0, scan.total_findings)

            # --- Persist real recon data ---
            scan.recon_dns_json = assessment.get("dns_data")
            scan.recon_whois_json = assessment.get("whois_data")
            scan.recon_ports_json = assessment.get("open_ports")
            scan.recon_services_json = assessment.get("services")
            scan.recon_os_json = assessment.get("os_info")
            scan.endpoints_json = assessment.get("crawl_result", {}).get("pages")
            scan.adaptive_json = assessment.get("adaptive_summary")

            # --- Finding lifecycle correlation ---
            try:
                from app.services.correlation_service import CorrelationService
                correlation_service = CorrelationService(self.db)
                correlation_counts = await correlation_service.correlate_scan_findings(scan.id, scan.target_id)
                scan.correlation_json = correlation_counts
            except Exception:
                logger.exception("Correlation failed for scan %s", scan.id)

            counters = assessment.get("counters", {})
            scan.requests_count = counters.get("requests_made", 0)
            scan.endpoints_count = counters.get("endpoints_discovered", 0)

            target.last_scan_id = scan.id
            target.validated_at = datetime.now(UTC)
            target.risk_score = float(assessment["statistics"].get("overall_risk_score", 0.0))

            # Store live telemetry snapshot in summary_json so state survives server reloads
            bucket = _get_telemetry_bucket(scan.id)
            for m in bucket["modules"].values():
                m["status"] = "Complete"
                m["progress"] = 100

            summary = dict(scan.summary_json or {})
            summary["live_telemetry"] = {
                "events": bucket.get("events", []),
                "modules": list(bucket.get("modules", {}).values()),
                "eta_seconds": 0,
                "target_url": target.url,
                "report_id": bucket.get("report_id"),
            }
            scan.summary_json = summary

            await self.db.commit()

            try:
                report = await self.report_service.generate_report(user, scan.id, "pdf")
                if report:
                    bucket["report_id"] = report.id
                    summary["live_telemetry"]["report_id"] = report.id
                    scan.summary_json = summary
                    await self.db.commit()
            except Exception:
                logger.exception("Report generation failed for scan %s", scan.id)

            await connection_manager.broadcast(scan.id, {
                "event": "scan_completed",
                "scan_id": scan.id,
                "progress": 100,
                "total_findings": scan.total_findings,
                "current_module": "Complete",
                "current_url": target.url,
                "requests_count": counters.get("requests_made", 0),
                "endpoints_count": counters.get("endpoints_discovered", 0),
                "findings_count": counters.get("findings_count", 0),
                "open_ports": counters.get("open_ports", 0),
                "services_count": counters.get("services_detected", 0),
                "eta_seconds": 0,
                "log": {
                    "time": datetime.now(UTC).strftime("%H:%M:%S"),
                    "level": "SCAN",
                    "message": f"Scan completed — {scan.total_findings} findings",
                },
            })
        except asyncio.CancelledError:
            logger.info("Scan %s execution cancelled by user", scan.id)
            scan.status = "cancelled"
            scan.error_message = "Scan cancelled by user"
            scan.current_module = "Cancelled"
            scan.completed_at = datetime.now(UTC)
            scan.duration_seconds = safe_duration(scan.started_at, scan.completed_at)
            bucket = _get_telemetry_bucket(scan.id)
            summary = dict(scan.summary_json or {})
            summary["live_telemetry"] = {
                "events": bucket.get("events", []),
                "modules": list(bucket.get("modules", {}).values()),
                "eta_seconds": 0,
                "target_url": getattr(scan, "current_url", "") or "",
                "report_id": None,
            }
            scan.summary_json = summary
            try:
                await self.db.commit()
            except Exception:
                await self.db.rollback()
            await connection_manager.broadcast(scan.id, {
                "event": "scan_cancelled",
                "scan_id": scan.id,
                "progress": scan.progress_percent,
                "status": "cancelled",
                "current_module": "Cancelled",
                "log": {
                    "time": datetime.now(UTC).strftime("%H:%M:%S"),
                    "level": "WARN",
                    "message": "Scan execution cancelled by user. Stopped all active probes.",
                },
            })
            raise
        except Exception as exc:
            logger.exception("[SCAN_FAILURE] scan_id=%s error_type=%s error_message=%s", scan_id, type(exc).__name__, exc)
            try:
                await self.db.rollback()
                result = await self.db.execute(select(Scan).where(Scan.id == scan_id))
                failed_scan = result.scalar_one_or_none()
                if failed_scan:
                    failed_scan.status = "failed"
                    failed_scan.error_message = str(exc)
                    failed_scan.completed_at = datetime.now(UTC)
                    failed_scan.duration_seconds = safe_duration(failed_scan.started_at, failed_scan.completed_at)
                    bucket = _get_telemetry_bucket(scan_id)
                    summary = dict(failed_scan.summary_json or {})
                    summary["live_telemetry"] = {
                        "events": bucket.get("events", []),
                        "modules": list(bucket.get("modules", {}).values()),
                        "eta_seconds": 0,
                        "target_url": getattr(failed_scan, "current_url", "") or "",
                        "report_id": None,
                    }
                    failed_scan.summary_json = summary
                    await self.db.commit()
            except Exception as rollback_err:
                logger.warning(f"Error while recording scan failure: {rollback_err}")

            await connection_manager.broadcast(scan_id, {
                "event": "scan_failed",
                "scan_id": scan_id,
                "progress": getattr(scan, "progress_percent", 0),
                "error": str(exc),
                "log": {
                    "time": datetime.now(UTC).strftime("%H:%M:%S"),
                    "level": "FOUND",
                    "message": f"Scan failed: {exc}",
                },
            })
            raise

        await self.db.refresh(scan)
        return scan

    async def cancel_scan(self, user: User, scan_id: str) -> ScanRead:
        result = await self.db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
        scan = result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

        if scan.status in {"completed", "failed", "cancelled"}:
            return self._to_read(scan)

        task = _active_scan_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()

        scan.status = "cancelled"
        scan.current_module = "Cancelled"
        scan.error_message = "Scan cancelled by user"
        scan.completed_at = datetime.now(UTC)
        scan.duration_seconds = safe_duration(scan.started_at, scan.completed_at)
        try:
            await self.db.commit()
        except Exception:
            await self.db.rollback()

        await connection_manager.broadcast(scan_id, {
            "event": "scan_cancelled",
            "scan_id": scan_id,
            "progress": scan.progress_percent,
            "status": "cancelled",
            "current_module": "Cancelled",
            "log": {
                "time": datetime.now(UTC).strftime("%H:%M:%S"),
                "level": "WARN",
                "message": "Scan execution cancelled by user. Stopped all active probes.",
            },
        })

        return self._to_read(scan)

    async def get_scan(self, user: User, scan_id: str) -> ScanRead:
        result = await self.db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
        scan = result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        target_res = await self.db.execute(select(Target).where(Target.id == scan.target_id))
        target = target_res.scalar_one_or_none()
        if target:
            scan.target = target
        return self._to_read(scan)

    async def get_active_scan(self, user: User) -> ScanRead | None:
        """Find the currently running scan for the user, or fallback to the most recent scan."""
        # 1. First priority: Scan with an actively executing background task in this process
        running_task_ids = [sid for sid, task in _active_scan_tasks.items() if not task.done()]
        if running_task_ids:
            query = (
                select(Scan)
                .where(Scan.user_id == user.id, Scan.id.in_(running_task_ids))
                .order_by(Scan.created_at.desc())
            )
            res = await self.db.execute(query)
            active_scan = res.scalars().first()
            if active_scan:
                target_res = await self.db.execute(select(Target).where(Target.id == active_scan.target_id))
                target = target_res.scalar_one_or_none()
                if target:
                    active_scan.target = target
                return self._to_read(active_scan)

        # 2. Second priority: Any scan marked running/queued in database
        query = (
            select(Scan)
            .where(Scan.user_id == user.id, Scan.status.in_(["running", "queued"]))
            .order_by(Scan.created_at.desc())
        )
        result = await self.db.execute(query)
        active_scan = result.scalars().first()
        if active_scan:
            target_res = await self.db.execute(select(Target).where(Target.id == active_scan.target_id))
            target = target_res.scalar_one_or_none()
            if target:
                active_scan.target = target
            return self._to_read(active_scan)

        # 3. Fallback: User's most recent scan
        fallback_query = (
            select(Scan)
            .where(Scan.user_id == user.id)
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        result = await self.db.execute(fallback_query)
        recent_scan = result.scalars().first()
        if recent_scan:
            target_res = await self.db.execute(select(Target).where(Target.id == recent_scan.target_id))
            target = target_res.scalar_one_or_none()
            if target:
                recent_scan.target = target
            return self._to_read(recent_scan)

        return None

    async def list_scans(self, user: User) -> list[ScanRead]:
        result = await self.db.execute(select(Scan).where(Scan.user_id == user.id).order_by(Scan.created_at.desc()))
        scans = result.scalars().all()
        # Preload targets for all scans
        target_ids = list({s.target_id for s in scans})
        targets_map = {}
        if target_ids:
            t_res = await self.db.execute(select(Target).where(Target.id.in_(target_ids)))
            targets_map = {t.id: t for t in t_res.scalars().all()}
        for s in scans:
            if s.target_id in targets_map:
                s.target = targets_map[s.target_id]
        return [self._to_read(scan) for scan in scans]

    async def _update_scan_progress(self, scan: Scan, payload: dict[str, Any]) -> None:
        scan.current_module = payload.get("current_module", scan.current_module)
        scan.current_url = payload.get("current_url", scan.current_url)
        scan.progress_percent = int(payload.get("progress", scan.progress_percent))
        if payload.get("findings_count") is not None:
            scan.total_findings = int(payload["findings_count"])
        elif payload.get("finding"):
            scan.total_findings += 1

        bucket = _get_telemetry_bucket(scan.id)
        if payload.get("eta_seconds") is not None:
            bucket["eta_seconds"] = int(payload["eta_seconds"])
        if payload.get("current_url"):
            bucket["target_url"] = payload.get("current_url")

        # Capture log entry
        log_entry = payload.get("log")
        if log_entry and isinstance(log_entry, dict) and log_entry.get("message"):
            event_data = {
                "time": log_entry.get("time") or datetime.now(UTC).strftime("%H:%M:%S"),
                "level": log_entry.get("level") or "INFO",
                "message": log_entry.get("message"),
            }
            bucket["events"].insert(0, event_data)
            if len(bucket["events"]) > 150:
                bucket["events"].pop()

        # Capture module card info
        mod_name = None
        mod_status = None
        mod_findings = None
        if payload.get("module_info") and isinstance(payload["module_info"], dict):
            mod_info = payload["module_info"]
            mod_name = mod_info.get("name")
            mod_status = mod_info.get("status")
            mod_findings = mod_info.get("findings")
        elif payload.get("current_module"):
            mod_name = payload["current_module"]
            mod_status = "Complete" if payload.get("event") == "module_complete" else "Scanning"

        if mod_name:
            norm_key = _normalize_mod_key(mod_name)
            target_key = norm_key
            for k in bucket["modules"]:
                if k == norm_key or (len(k) > 4 and (k in norm_key or norm_key in k)):
                    target_key = k
                    break

            if target_key not in bucket["modules"]:
                curr_max = max([m.get("order", 0) for m in bucket["modules"].values()] or [0])
                bucket["modules"][target_key] = {
                    "name": mod_name,
                    "status": mod_status or "Scanning",
                    "progress": 100 if mod_status == "Complete" else int(payload.get("progress") or 50),
                    "findings": int(mod_findings or 0),
                    "order": curr_max + 1,
                }

            current_mod = bucket["modules"][target_key]
            current_order = current_mod.get("order", 0)

            current_mod["status"] = mod_status or "Scanning"
            current_mod["progress"] = 100 if mod_status == "Complete" else int(payload.get("progress") or 50)
            if mod_findings is not None:
                current_mod["findings"] = int(mod_findings)

            # Strict incremental progression:
            # - Modules preceding the active module in pipeline MUST be Complete (100%)
            # - Modules following the active module MUST be Queued (0%), never Complete
            for k, m in bucket["modules"].items():
                m_order = m.get("order", 0)
                if m_order < current_order:
                    m["status"] = "Complete"
                    m["progress"] = 100
                elif m_order > current_order:
                    m["status"] = "Queued"
                    m["progress"] = 0

        # Throttle DB commits to prevent high-frequency write contention and async session collisions
        now = time.monotonic()
        if (now - self._last_db_commit > 1.5) or (scan.progress_percent >= 100):
            self._last_db_commit = now
            if not self._progress_lock.locked():
                async with self._progress_lock:
                    try:
                        await self.db.commit()
                    except Exception:
                        try:
                            await self.db.rollback()
                        except Exception:
                            pass

    async def _persist_findings(self, scan: Scan, findings: list[dict[str, Any]]) -> list[Finding]:
        persisted: list[Finding] = []
        seen_fingerprints: dict[str, Finding] = {}
        verification_queue: list[tuple[str, dict[str, Any]]] = []
        for raw in findings:
            method = "GET"
            if raw.get("http_request"):
                try:
                    req_data = json.loads(raw["http_request"])
                    method = req_data.get("method", "GET")
                except Exception:
                    pass

            target = str(scan.target_id)
            url = str(raw.get("affected_url") or "")
            param = str(raw.get("affected_parameter") or "")
            finding_type = str(raw.get("finding_type") or raw.get("type", "information_disclosure"))
            cwe = str(raw.get("cwe_id", "CWE-200"))

            # Prefer root-cause correlation_key from pipeline if available
            corr_key = raw.get("correlation_key")
            if corr_key:
                fingerprint = f"{target}|{corr_key}"
            else:
                fingerprint = f"{target}|{url}|{method}|{param}|{finding_type}|{cwe}"

            if fingerprint in seen_fingerprints:
                existing = seen_fingerprints[fingerprint]
                new_evidence = raw.get("evidence")
                if new_evidence and new_evidence not in (existing.evidence or ""):
                    if existing.evidence:
                        existing.evidence += f"\n\n---\n\n{new_evidence}"
                    else:
                        existing.evidence = new_evidence
                continue

            finding = Finding(
                scan_id=scan.id,
                project_id=scan.project_id,
                target_id=scan.target_id,
                source_module=raw.get("source_module", raw.get("finding_type", "unknown")),
                finding_type=finding_type,
                title=raw.get("title", "Security Finding"),
                description=raw.get("description", ""),
                evidence=raw.get("evidence"),
                affected_url=raw.get("affected_url"),
                affected_parameter=raw.get("affected_parameter"),
                http_request=raw.get("http_request"),
                http_response=raw.get("http_response"),
                owasp_category=raw.get("owasp_category", "A05:2021 - Security Misconfiguration"),
                cwe_id=cwe,
                cwe_name=raw.get("cwe_name", "Information Exposure"),
                cvss_score=raw.get("cvss_score", 4.3),
                cvss_vector=raw.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
                severity=raw.get("severity", "Low"),
                confidence=raw.get("confidence", "Medium"),
                risk_rating=raw.get("risk_rating", "Low"),
                remediation=raw.get("remediation", "Review the finding and apply secure coding fixes."),
                best_practices=raw.get("best_practices"),
                secure_coding=raw.get("secure_coding"),
                verification_guidance=raw.get("verification_guidance"),
                references_json=raw.get("references_json") or [],
                status=raw.get("status", "open"),
                metadata_json=raw.get("metadata_json") or {},
            )
            self.db.add(finding)
            await self.db.flush()
            seen_fingerprints[fingerprint] = finding
            persisted.append(finding)
            
            analysis = self.ai_service.generate_finding_analysis(raw)
            
            # Attach structured verification metadata preserving scanner classification
            finding_meta = dict(finding.metadata_json or {})
            finding_meta["scanner_result"] = {
                "confidence": finding.confidence,
                "severity": finding.severity,
                "source_module": finding.source_module,
            }
            finding_meta["verification"] = {
                "deterministic": {
                    "verdict": analysis.get("verification_verdict", "POTENTIAL"),
                    "confidence": analysis.get("verification_confidence", 0.50),
                    "reasoning": analysis.get("verification_reasoning", ""),
                },
                "ai": {
                    "verdict": analysis.get("verification_verdict", "POTENTIAL"),
                    "confidence": analysis.get("verification_confidence", 0.50),
                    "reasoning": analysis.get("verification_reasoning", ""),
                },
                "final_classification": analysis.get("verification_verdict", "POTENTIAL"),
            }
            finding.metadata_json = finding_meta

            self.db.add(
                AIAnalysis(
                    scan_id=scan.id,
                    finding_id=finding.id,
                    simple_explanation=analysis["simple_explanation"],
                    technical_explanation=analysis["technical_explanation"],
                    business_impact=analysis["business_impact"],
                    risk_explanation=analysis["risk_explanation"],
                    owasp_explanation=analysis["owasp_explanation"],
                    cwe_explanation=analysis["cwe_explanation"],
                    remediation_steps_json=analysis["remediation_steps_json"],
                    best_practices_json=analysis["best_practices_json"],
                    secure_coding_recommendation=analysis["secure_coding_recommendation"],
                    verification_guidance=analysis["verification_guidance"],
                    code_example=analysis["code_example"],
                    references_json=analysis["references_json"],
                    verification_verdict=analysis.get("verification_verdict", "POTENTIAL"),
                    verification_reasoning=analysis.get("verification_reasoning"),
                    verification_confidence=analysis.get("verification_confidence", 0.50),
                    context_json={"finding_type": finding.finding_type, "title": finding.title},
                )
            )
            verification_queue.append((finding.id, raw))
        await self.db.commit()

        # Non-blocking asynchronous background AI verification
        if verification_queue:
            asyncio.create_task(self._async_ai_verify_findings(verification_queue))

        return persisted

    async def _async_ai_verify_findings(self, queue: list[tuple[str, dict[str, Any]]]) -> None:
        """Non-blocking background AI verification worker to eliminate scanner latency."""
        try:
            async with AsyncSessionLocal() as session:
                for finding_id, raw_data in queue:
                    try:
                        verification = await self.ai_verifier.verify_finding(raw_data)
                        
                        # Update AIAnalysis record
                        stmt = select(AIAnalysis).where(AIAnalysis.finding_id == finding_id)
                        res = await session.execute(stmt)
                        ai_record = res.scalar_one_or_none()
                        if ai_record:
                            ai_record.verification_verdict = verification["final_classification"]
                            ai_record.verification_reasoning = verification["verification_reasoning"]
                            ai_record.verification_confidence = verification["verification_confidence"]

                        # Update Finding metadata
                        finding_stmt = select(Finding).where(Finding.id == finding_id)
                        finding_res = await session.execute(finding_stmt)
                        f_record = finding_res.scalar_one_or_none()
                        if f_record:
                            f_meta = dict(f_record.metadata_json or {})
                            f_meta["verification"] = {
                                "deterministic": verification["deterministic_verification"],
                                "ai": verification["ai_verification"],
                                "final_classification": verification["final_classification"],
                            }
                            f_record.metadata_json = f_meta
                    except Exception as item_err:
                        logger.warning(f"Async AI verification failed for finding {finding_id}: {item_err}")
                await session.commit()
        except Exception as batch_err:
            logger.warning(f"Async AI verification batch encountered error: {batch_err}")

    def _to_read(self, scan: Scan) -> ScanRead:
        data = {
            "id": scan.id,
            "project_id": scan.project_id,
            "target_id": scan.target_id,
            "user_id": scan.user_id,
            "scan_type": scan.scan_type,
            "depth": scan.depth,
            "status": scan.status,
            "progress_percent": scan.progress_percent,
            "current_module": scan.current_module,
            "current_url": scan.current_url,
            "total_findings": scan.total_findings,
            "requests_count": scan.requests_count,
            "endpoints_count": scan.endpoints_count,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "duration_seconds": scan.duration_seconds,
            "error_message": scan.error_message,
            "statistics_json": scan.statistics_json,
            "summary_json": scan.summary_json,
            "auth_config_json": scan.auth_config_json,
            "adaptive_json": scan.adaptive_json,
            "correlation_json": scan.correlation_json,
        }

        # Canonical target URL
        target_url = None
        if "target" in scan.__dict__ and scan.__dict__["target"]:
            target_url = getattr(scan.__dict__["target"], "url", None)

        # Check in-memory telemetry bucket first
        bucket = _live_telemetry_cache.get(scan.id)
        if bucket:
            data["live_events"] = bucket.get("events", [])
            data["live_modules"] = list(bucket.get("modules", {}).values())
            data["eta_seconds"] = bucket.get("eta_seconds", 0)
            if not target_url and bucket.get("target_url"):
                target_url = bucket.get("target_url")
            if bucket.get("report_id"):
                data["report_id"] = bucket.get("report_id")
        elif scan.summary_json and isinstance(scan.summary_json, dict) and "live_telemetry" in scan.summary_json:
            persisted = scan.summary_json["live_telemetry"]
            data["live_events"] = persisted.get("events", [])
            data["live_modules"] = persisted.get("modules", [])
            data["eta_seconds"] = persisted.get("eta_seconds", 0)
            if not target_url and persisted.get("target_url"):
                target_url = persisted.get("target_url")
            if persisted.get("report_id"):
                data["report_id"] = persisted.get("report_id")

        data["target_url"] = target_url or scan.current_url

        # Direct report association check if available in identity map
        if not data.get("report_id") and "reports" in scan.__dict__ and scan.__dict__["reports"]:
            data["report_id"] = scan.__dict__["reports"][0].id

        return ScanRead.model_validate(data)
