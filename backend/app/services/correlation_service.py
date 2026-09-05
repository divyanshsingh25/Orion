"""ORION Finding Correlation Service.

After a scan completes, correlates new findings against historical findings
for the same target to track lifecycle state:
  - NEW: First time this finding has been seen
  - CONFIRMED: Previously seen and detected again
  - FIXED: Previously seen but not in latest scan
  - REOPENED: Was FIXED, now detected again
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from sqlalchemy import select, and_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding

logger = logging.getLogger("orion.correlation")


def compute_correlation_key(finding: dict[str, Any] | Finding) -> str:
    """Compute a deterministic hash for cross-scan finding matching.

    The key is based on:
      - target_id
      - finding_type
      - affected_url (normalized)
      - affected_parameter
      - cwe_id

    This means the same vulnerability at the same location produces the
    same key across different scans.
    """
    if isinstance(finding, Finding):
        parts = [
            str(finding.target_id),
            str(finding.finding_type),
            _normalize_url_for_key(str(finding.affected_url or "")),
            str(finding.affected_parameter or ""),
            str(finding.cwe_id or ""),
        ]
    else:
        parts = [
            str(finding.get("target_id", "")),
            str(finding.get("finding_type", finding.get("type", ""))),
            _normalize_url_for_key(str(finding.get("affected_url", ""))),
            str(finding.get("affected_parameter", "")),
            str(finding.get("cwe_id", "")),
        ]

    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _normalize_url_for_key(url: str) -> str:
    """Normalize a URL for consistent correlation key generation."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        # Remove fragments, normalize path
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    except Exception:
        return url


class CorrelationService:
    """Correlates findings across scans for lifecycle tracking."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def correlate_scan_findings(
        self,
        scan_id: str,
        target_id: str,
    ) -> dict[str, int]:
        """Correlate findings from a completed scan against historical findings.

        Updates lifecycle_status on all relevant findings.
        Returns a summary of status counts.
        """
        counts = {"new": 0, "confirmed": 0, "fixed": 0, "reopened": 0}

        # Get all findings from the current scan
        current_result = await self.db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        current_findings = list(current_result.scalars().all())

        if not current_findings:
            return counts

        # Compute correlation keys for current findings
        current_keys: dict[str, Finding] = {}
        for f in current_findings:
            key = compute_correlation_key(f)
            f.correlation_key = key
            current_keys[key] = f

        # Get all historical findings for this target (from other scans)
        historical_result = await self.db.execute(
            select(Finding).where(
                and_(
                    Finding.target_id == target_id,
                    Finding.scan_id != scan_id,
                )
            ).order_by(Finding.created_at.desc())
        )
        historical_findings = list(historical_result.scalars().all())

        # Build a map of historical correlation keys
        historical_keys: dict[str, Finding] = {}
        for f in historical_findings:
            key = f.correlation_key or compute_correlation_key(f)
            if key not in historical_keys:
                historical_keys[key] = f

        # Classify current findings
        for key, finding in current_keys.items():
            if key in historical_keys:
                historical = historical_keys[key]
                prev_status = historical.lifecycle_status or "new"

                if prev_status == "fixed":
                    finding.lifecycle_status = "reopened"
                    finding.first_seen_scan_id = historical.first_seen_scan_id or historical.scan_id
                    counts["reopened"] += 1
                else:
                    finding.lifecycle_status = "confirmed"
                    finding.first_seen_scan_id = historical.first_seen_scan_id or historical.scan_id
                    counts["confirmed"] += 1
            else:
                finding.lifecycle_status = "new"
                finding.first_seen_scan_id = scan_id
                counts["new"] += 1

            finding.last_seen_scan_id = scan_id

        # Mark historical findings NOT in current scan as "fixed"
        # (only for the most recent prior scan's findings)
        if historical_findings:
            # Get the most recent prior scan ID
            prior_scan_ids: set[str] = set()
            for f in historical_findings:
                prior_scan_ids.add(f.scan_id)

            # Only consider the most recent prior scan for "fixed" determination
            most_recent_prior_findings = [
                f for f in historical_findings
                if f.scan_id == historical_findings[0].scan_id
            ]

            for f in most_recent_prior_findings:
                key = f.correlation_key or compute_correlation_key(f)
                if key not in current_keys:
                    # Was in previous scan, not in current → fixed
                    if f.lifecycle_status not in ("fixed",):
                        f.lifecycle_status = "fixed"
                        f.last_seen_scan_id = f.scan_id  # Last seen in previous scan
                        counts["fixed"] += 1

        try:
            await self.db.commit()
        except Exception:
            await self.db.rollback()
            logger.exception("Failed to commit correlation updates")

        logger.info(
            "Correlation for scan %s: %d new, %d confirmed, %d fixed, %d reopened",
            scan_id, counts["new"], counts["confirmed"], counts["fixed"], counts["reopened"],
        )

        return counts
