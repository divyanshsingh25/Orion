from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import Finding, Report, Scan, User
from app.schemas.report import ReportRead
from app.services.ai_service import AIService


class ReportService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.settings = get_settings()
        self.ai_service = AIService()

    async def list_reports(self, user: User, project_id: str | None = None, scan_id: str | None = None) -> list[ReportRead]:
        query = select(Report).join(Report.scan).where(Scan.user_id == user.id)
        if project_id:
            query = query.where(Report.project_id == project_id)
        if scan_id:
            query = query.where(Report.scan_id == scan_id)
        result = await self.db.execute(query.order_by(Report.generated_at.desc()))
        return [ReportRead.model_validate(report) for report in result.scalars().all()]

    async def delete_report(self, user: User, report_id: str) -> None:
        result = await self.db.execute(select(Report).join(Report.scan).where(Report.id == report_id, Scan.user_id == user.id))
        report = result.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
        if report.file_path:
            try:
                Path(report.file_path).unlink(missing_ok=True)
            except Exception:
                pass
        await self.db.delete(report)
        await self.db.commit()

    async def generate_report(self, user: User, scan_id: str, report_format: str = "json") -> ReportRead:
        scan = await self._get_scan(user, scan_id)
        findings_result = await self.db.execute(select(Finding).where(Finding.scan_id == scan.id))
        findings = list(findings_result.scalars().all())
        severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        findings.sort(
            key=lambda f: (severity_rank.get((f.severity or "").lower(), 0), float(f.cvss_score or 0)),
            reverse=True,
        )
        payload = self._build_report_payload(scan, findings)

        report_dir = Path(self.settings.report_dir)
        report_dir.mkdir(parents=True, exist_ok=True)
        target_name = scan.target.host if scan.target and scan.target.host else "orion_report"
        filename = f"{target_name}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
        if report_format == "json":
            file_path = report_dir / f"{filename}.json"
            file_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        elif report_format == "csv":
            file_path = report_dir / f"{filename}.csv"
            self._write_csv(file_path, findings)
        elif report_format == "pdf":
            file_path = report_dir / f"{filename}.pdf"
            self._write_pdf(file_path, payload)
        elif report_format == "html":
            file_path = report_dir / f"{filename}.html"
            self._write_html(file_path, payload)
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported report format")

        report = Report(
            scan_id=scan.id,
            project_id=scan.project_id,
            target_id=scan.target_id,
            report_format=report_format,
            file_path=str(file_path),
            file_size=file_path.stat().st_size if file_path.exists() else None,
            executive_summary=payload["executive_summary"],
            overall_risk_score=payload["overall_risk_score"],
            severity_distribution_json=payload["severity_distribution"],
            owasp_breakdown_json=payload["owasp_breakdown"],
            cwe_mapping_json=payload["cwe_mapping"],
            cvss_analysis_json=payload["cvss_analysis"],
        )
        self.db.add(report)
        await self.db.commit()
        await self.db.refresh(report)

        try:
            from app.services.email_report_service import EmailReportService
            import asyncio
            asyncio.create_task(EmailReportService.send_scan_report_email_bg(scan.id, user.id, report.id))
        except Exception as bg_err:
            logger.warning("Could not dispatch background report delivery email: %s", bg_err)

        return ReportRead.model_validate(report)

    async def _get_scan(self, user: User, scan_id: str) -> Scan:
        result = await self.db.execute(select(Scan).options(joinedload(Scan.target)).where(Scan.id == scan_id, Scan.user_id == user.id))
        scan = result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        return scan

    def _build_report_payload(self, scan: Scan, findings: list[Finding]) -> dict[str, Any]:
        severity_counts = Counter((finding.severity or "info").lower() for finding in findings)
        owasp_breakdown = Counter(finding.owasp_category for finding in findings)
        cwe_mapping = Counter(finding.cwe_id for finding in findings)
        cvss_buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            score = float(finding.cvss_score)
            if score >= 9:
                cvss_buckets["critical"] += 1
            elif score >= 7:
                cvss_buckets["high"] += 1
            elif score >= 4:
                cvss_buckets["medium"] += 1
            else:
                cvss_buckets["low"] += 1

        overall_risk = min(100.0, sum({"critical": 20, "high": 12, "medium": 6, "low": 2}.get(severity, 0) * count for severity, count in severity_counts.items()))

        # --- Extract real recon data from scan ---
        recon = scan.summary_json.get("recon", {}) if scan.summary_json else {}
        dns_info = scan.recon_dns_json or {}
        whois_info = scan.recon_whois_json or {}
        ports_info = scan.recon_ports_json or []
        services_info = scan.recon_services_json or []
        os_info = scan.recon_os_json or {}
        endpoints_info = scan.endpoints_json or []

        # Build rich executive summary from REAL data
        port_count = len([p for p in ports_info if isinstance(p, dict) and p.get("state") == "open"])
        service_count = len(services_info)
        endpoint_count = scan.endpoints_count or 0
        duration_str = f"{scan.duration_seconds:.1f}s" if scan.duration_seconds else "N/A"

        exec_parts = [
            f"ORION identified {len(findings)} findings during a {scan.scan_type} assessment.",
        ]
        if port_count:
            exec_parts.append(f"{port_count} open ports were discovered.")
        if service_count:
            svc_names = ", ".join(s.get("service", "Unknown") for s in services_info[:5] if isinstance(s, dict))
            exec_parts.append(f"{service_count} services identified ({svc_names}).")
        if endpoint_count:
            exec_parts.append(f"{endpoint_count} endpoints crawled.")
        exec_parts.append(f"Scan duration: {duration_str}.")
        if severity_counts.get("critical", 0) > 0:
            exec_parts.append(f"CRITICAL: {severity_counts['critical']} critical vulnerabilities require immediate attention.")
        elif severity_counts.get("high", 0) > 0:
            exec_parts.append(f"{severity_counts['high']} high-severity issues should be prioritized.")

        findings_payload = []
        for finding in findings:
            f_dict = self._finding_to_dict(finding)
            f_dict["ai_analysis"] = self.ai_service.generate_finding_analysis(f_dict)
            findings_payload.append(f_dict)

        return {
            "scan_id": scan.id,
            "project_id": scan.project_id,
            "target_id": scan.target_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "executive_summary": " ".join(exec_parts),
            "overall_risk_score": round(overall_risk, 2),
            "severity_distribution": dict(severity_counts),
            "owasp_breakdown": dict(owasp_breakdown),
            "cwe_mapping": dict(cwe_mapping),
            "cvss_analysis": cvss_buckets,
            # --- Real recon sections ---
            "scan_info": {
                "target": recon.get("url", ""),
                "scan_type": scan.scan_type,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration_seconds": scan.duration_seconds,
                "requests_made": scan.requests_count or 0,
                "endpoints_discovered": scan.endpoints_count or 0,
            },
            "dns_information": {
                "records": dns_info.get("records", {}),
                "subdomains": [s.get("subdomain") for s in dns_info.get("subdomains", []) if isinstance(s, dict)],
            },
            "whois_information": whois_info,
            "name_servers": dns_info.get("records", {}).get("NS", []) if isinstance(dns_info.get("records"), dict) else [],
            "ip_addresses": [
                r.get("value") for r in dns_info.get("records", {}).get("A", [])
                if isinstance(r, dict) and r.get("value")
            ] if isinstance(dns_info.get("records"), dict) else [],
            "open_ports": [
                {"port": p.get("port"), "protocol": p.get("protocol"), "state": p.get("state"),
                 "service": p.get("service"), "banner": (p.get("banner") or "")[:100]}
                for p in ports_info if isinstance(p, dict)
            ],
            "services": [
                {"service": s.get("service"), "version": s.get("version"), "port": s.get("port"),
                 "confidence": s.get("confidence")}
                for s in services_info if isinstance(s, dict)
            ],
            "os_detection": os_info,
            "technologies": recon.get("technologies", []),
            "endpoints": [
                {"url": e.get("url"), "status": e.get("status")}
                for e in endpoints_info[:50] if isinstance(e, dict)
            ],
            "tls": recon.get("tls", {}),
            "findings": findings_payload,
        }

    def _finding_to_dict(self, finding: Finding) -> dict[str, Any]:
        return {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "affected_url": finding.affected_url,
            "affected_parameter": finding.affected_parameter,
            "finding_type": finding.finding_type,
            "owasp_category": finding.owasp_category,
            "cwe_id": finding.cwe_id,
            "cwe_name": finding.cwe_name,
            "cvss_score": float(finding.cvss_score),
            "cvss_vector": finding.cvss_vector,
            "remediation": finding.remediation,
            "evidence": finding.evidence,
            "confidence": finding.confidence,
            "source_module": finding.source_module,
            "verification_guidance": finding.verification_guidance,
            "lifecycle_status": getattr(finding, "lifecycle_status", "new"),
        }

    def _write_csv(self, file_path: Path, findings: list[Finding]) -> None:
        with file_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["title", "severity", "owasp_category", "cwe_id", "cvss_score", "affected_url", "evidence", "remediation"])
            writer.writeheader()
            for finding in findings:
                writer.writerow({"title": finding.title, "severity": finding.severity, "owasp_category": finding.owasp_category, "cwe_id": finding.cwe_id, "cvss_score": float(finding.cvss_score), "affected_url": finding.affected_url, "evidence": finding.evidence, "remediation": finding.remediation})

    def _write_pdf(self, file_path: Path, payload: dict[str, Any]) -> None:
        from app.reports.generator import ReportGenerator
        ReportGenerator.generate_pdf(payload, str(file_path))

    def _write_html(self, file_path: Path, payload: dict[str, Any]) -> None:
        findings = payload.get("findings", [])
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {payload.get('scan_info', {}).get('target', 'ORION')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #1e293b; background: #f8fafc; margin: 0; padding: 2rem; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #ffffff; border-radius: 12px; padding: 2.5rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
        h1, h2, h3 {{ color: #0f172a; }}
        .badge {{ display: inline-block; padding: 0.25rem 0.5rem; border-radius: 6px; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
        .badge-critical {{ background: #fee2e2; color: #dc2626; }}
        .badge-high {{ background: #ffedd5; color: #ea580c; }}
        .badge-medium {{ background: #fef9c3; color: #ca8a04; }}
        .badge-low {{ background: #ccfbf1; color: #0f766e; }}
        .badge-info {{ background: #e0f2fe; color: #0284c7; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f1f5f9; font-weight: 600; }}
        .finding-card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; background: #fff; }}
        .code-box {{ background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 6px; font-family: monospace; font-size: 0.85rem; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> {payload.get('scan_info', {}).get('target', 'N/A')}</p>
        <p><strong>Date:</strong> {payload.get('generated_at', '')}</p>
        <hr/>
        <h2>1. Executive Summary</h2>
        <p>{payload.get('executive_summary', '')}</p>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Overall Risk Score</td><td>{payload.get('overall_risk_score', 0):.2f}</td></tr>
            <tr><td>Total Findings</td><td>{len(findings)}</td></tr>
            <tr><td>Critical / High</td><td>{payload.get('cvss_analysis', {}).get('critical', 0)} / {payload.get('cvss_analysis', {}).get('high', 0)}</td></tr>
        </table>
        <h2>2. Detailed Findings ({len(findings)})</h2>
"""
        for idx, finding in enumerate(findings):
            sev = str(finding.get("severity", "Info")).lower()
            html_content += f"""
        <div class="finding-card">
            <h3>{idx+1}. {finding.get('title')}</h3>
            <p>
                <span class="badge badge-{sev}">{finding.get('severity')}</span>
                <strong>CVSS:</strong> {finding.get('cvss_score', 'N/A')} |
                <strong>OWASP:</strong> {finding.get('owasp_category', 'N/A')} |
                <strong>CWE:</strong> {finding.get('cwe_id', 'N/A')}
            </p>
            <p><strong>Asset:</strong> {finding.get('affected_url') or 'N/A'}</p>
            <p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>
            {f'<p><strong>Evidence:</strong></p><pre class="code-box">{finding.get("evidence")}</pre>' if finding.get("evidence") else ''}
            <p><strong>Remediation:</strong> {finding.get('remediation', 'N/A')}</p>
        </div>
"""
        html_content += """
    </div>
</body>
</html>"""
        file_path.write_text(html_content, encoding="utf-8")
