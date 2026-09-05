"""ORION Finding Validation Pipeline.

Central quality gate that all raw findings must pass through before being
accepted into the scan results:

    Detection → Evidence Enrichment → Verification → Deduplication
    → Severity/Confidence Recalculation → Final Finding

Deduplication uses a root-cause correlation key that groups findings by the
*underlying issue* while preserving individual endpoint evidence.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any


# ---------------------------------------------------------------------------
# Lifecycle statuses for finding tracking
# ---------------------------------------------------------------------------
LIFECYCLE_NEW = "new"
LIFECYCLE_CONFIRMED = "confirmed"
LIFECYCLE_POTENTIAL = "potential"
LIFECYCLE_FIXED = "fixed"
LIFECYCLE_REOPENED = "reopened"

# ---------------------------------------------------------------------------
# Minimum evidence requirements per finding type
# ---------------------------------------------------------------------------
_EVIDENCE_REQUIREMENTS: dict[str, list[str]] = {
    # Injection / active testing — expect payload + request/response
    "xss": ["affected_url", "source_module", "detection_reason"],
    "sqli": ["affected_url", "source_module", "detection_reason"],
    "nosqli": ["affected_url", "source_module", "detection_reason"],
    "ssrf": ["affected_url", "source_module", "detection_reason"],
    "ssti": ["affected_url", "source_module", "detection_reason"],
    "rce": ["affected_url", "source_module", "detection_reason"],
    "lfi": ["affected_url", "source_module", "detection_reason"],
    "path_traversal": ["affected_url", "source_module", "detection_reason"],
    "xxe": ["affected_url", "source_module", "detection_reason"],
    "ldapi": ["affected_url", "source_module", "detection_reason"],
    # Config / passive — no payload expected
    "security_headers": ["source_module"],
    "information_disclosure": ["source_module"],
    "tls_misconfiguration": ["source_module"],
    "cookie_security": ["source_module"],
    "service_vulnerability": ["source_module"],
    "csrf": ["affected_url", "source_module"],
    "cors": ["affected_url", "source_module"],
    "api_security": ["affected_url", "source_module"],
    "idor": ["affected_url", "source_module"],
    "open_redirect": ["affected_url", "source_module"],
}


def _build_correlation_key(finding: dict[str, Any]) -> str:
    """Build a root-cause correlation key for deduplication.

    The key captures the *underlying issue* so that the same vulnerability
    detected on different endpoints is grouped, but genuinely different
    vulnerabilities are NOT merged even if they share a CWE.

    Strategy per finding type:
      - security_headers / tls: type + header_name/check (same header missing
        on the same target is always one issue)
      - xss/sqli/injection: type + parameter + payload_signature (same vuln
        on different URLs with same param = one issue; different params = different)
      - api_security: type + sub-category (e.g. "permissive_methods") — grouped
        because it's a server config issue, not per-endpoint
      - cors: type + behavior (e.g. "reflects_origin") — same config issue
      - csrf: type + form_action_path (same form = one issue)
      - service_vulnerability: type + CVE ID (same CVE = one issue)
      - cookie_security: type + cookie_name
    """
    ftype = str(finding.get("finding_type") or finding.get("type") or "unknown")
    cwe = str(finding.get("cwe_id") or finding.get("cwe") or "")
    title = str(finding.get("title") or "")
    param = str(finding.get("affected_parameter") or finding.get("parameter") or
                finding.get("header_name") or finding.get("cookie_name") or "")

    # --- Type-specific key construction ---
    if "hsts" in title.lower() or "strict-transport-security" in str(param).lower() or "strict-transport-security" in title.lower():
        # Missing or misconfigured HSTS is the exact same underlying issue regardless of module (TLS vs Headers)
        key_parts = ["hsts_configuration", "cwe-319"]
    elif ftype in ("security_headers", "information_disclosure"):
        # Same missing header = one issue regardless of URL
        key_parts = [ftype, cwe, param]
    elif ftype == "tls_misconfiguration":
        # Normalize title to group same TLS issue
        normalized = re.sub(r"\d+", "#", title.lower())
        key_parts = [ftype, normalized]
    elif ftype == "service_vulnerability":
        # Group by CVE ID
        cve_id = str(finding.get("cve") or "")
        # If no CVE, use service + port as fallback
        if not cve_id:
            svc = str(finding.get("service") or "")
            port = str(finding.get("port") or "")
            key_parts = [ftype, svc, port]
        else:
            key_parts = [ftype, cve_id]
    elif ftype == "csrf":
        # Same form action path = one issue
        url = str(finding.get("affected_url") or finding.get("url") or "")
        from urllib.parse import urlparse
        path = urlparse(url).path
        key_parts = [ftype, path]
    elif ftype in ("cors", "api_security"):
        # Same underlying config issue — group by sub-category from title
        sub = _extract_subcategory(title)
        key_parts = [ftype, sub]
    elif ftype in ("xss", "sqli", "nosqli", "ssrf", "ssti", "rce", "lfi",
                    "path_traversal", "xxe", "ldapi"):
        # Same vuln type + same parameter = same root cause
        key_parts = [ftype, param]
    elif ftype == "open_redirect":
        key_parts = [ftype, param]
    elif ftype == "idor":
        key_parts = [ftype, param]
    else:
        # Fallback: type + CWE + normalized title
        normalized = re.sub(r'"[^"]*"', '"..."', title)
        normalized = re.sub(r"'[^']*'", "'...'", normalized)
        key_parts = [ftype, cwe, normalized]

    raw_key = "|".join(str(p).strip().lower() for p in key_parts)
    return hashlib.sha256(raw_key.encode()).hexdigest()[:16]


def _extract_subcategory(title: str) -> str:
    """Extract a normalized sub-category from a finding title."""
    title_lower = title.lower()
    if "cors" in title_lower and "reflects" in title_lower:
        return "cors_reflects_origin"
    if "cors" in title_lower and "wildcard" in title_lower:
        return "cors_wildcard"
    if "cors" in title_lower and "credentials" in title_lower:
        return "cors_credentials"
    if "permissive" in title_lower and "method" in title_lower:
        return "permissive_methods"
    if "trace" in title_lower:
        return "trace_enabled"
    if "data" in title_lower and "expos" in title_lower:
        return "data_exposure"
    return re.sub(r"[^a-z0-9]+", "_", title_lower)[:50]


def _validate_evidence(finding: dict[str, Any]) -> bool:
    """Check that a finding meets minimum evidence requirements."""
    ftype = str(finding.get("finding_type") or finding.get("type") or "unknown")
    required = _EVIDENCE_REQUIREMENTS.get(ftype, ["source_module"])
    for field in required:
        val = finding.get(field)
        if not val or str(val).strip() in ("", "None"):
            return False
    return True


def _enrich_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    """Add missing evidence fields with appropriate defaults.

    For findings that naturally have no payload (headers, TLS, CVEs),
    uses N/A rather than inventing data.
    """
    ftype = str(finding.get("finding_type") or finding.get("type") or "unknown")

    # Ensure detection_reason exists
    if not finding.get("detection_reason"):
        finding["detection_reason"] = (
            finding.get("detection") or
            finding.get("detection_technique") or
            finding.get("description") or
            "Detected by scanner module"
        )

    # Ensure verification_status exists
    if not finding.get("verification_status"):
        confidence = str(finding.get("confidence") or "").lower()
        if confidence == "confirmed":
            finding["verification_status"] = "confirmed"
        elif confidence in ("high", "medium"):
            finding["verification_status"] = "potential"
        else:
            finding["verification_status"] = "potential"

    # For passive/config findings, set payload-related fields to N/A
    passive_types = {
        "security_headers", "information_disclosure", "tls_misconfiguration",
        "cookie_security", "service_vulnerability",
    }
    if ftype in passive_types:
        if not finding.get("method"):
            finding["method"] = "N/A"
        if not finding.get("payload"):
            finding["payload"] = "N/A"
        if not finding.get("affected_parameter"):
            finding.setdefault("affected_parameter", finding.get("header_name") or
                               finding.get("cookie_name") or "N/A")

    # Lifecycle status
    if not finding.get("lifecycle_status"):
        vs = finding.get("verification_status", "potential")
        if vs == "confirmed":
            finding["lifecycle_status"] = LIFECYCLE_CONFIRMED
        elif vs == "rejected":
            finding["lifecycle_status"] = LIFECYCLE_FIXED
        else:
            finding["lifecycle_status"] = LIFECYCLE_NEW

    return finding


class FindingPipeline:
    """Central finding validation and deduplication pipeline."""

    def __init__(self) -> None:
        self._groups: dict[str, list[dict[str, Any]]] = {}
        self._rejected: list[dict[str, Any]] = []

    def process(self, raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Run all raw findings through the pipeline.

        Returns the validated, deduplicated list of findings.
        """
        self._groups.clear()
        self._rejected.clear()

        for finding in raw_findings:
            enriched = _enrich_evidence(finding)

            # Reject findings that fail minimum evidence requirements
            if not _validate_evidence(enriched):
                self._rejected.append(enriched)
                continue

            # Skip findings explicitly rejected by verification
            if enriched.get("verification_status") == "rejected":
                self._rejected.append(enriched)
                continue

            # Group by correlation key
            corr_key = _build_correlation_key(enriched)
            enriched["correlation_key"] = corr_key

            if corr_key not in self._groups:
                self._groups[corr_key] = []
            self._groups[corr_key].append(enriched)

        # Build final deduplicated findings
        results: list[dict[str, Any]] = []
        for corr_key, group in self._groups.items():
            if len(group) == 1:
                results.append(group[0])
            else:
                merged = self._merge_group(corr_key, group)
                results.append(merged)

        return results

    def _merge_group(self, corr_key: str, group: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge a group of related findings into a single finding.

        Keeps the highest-severity/confidence representative but preserves
        all individual endpoint evidence.
        """
        severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        confidence_rank = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}

        # Sort by severity then confidence — best representative first
        group.sort(key=lambda f: (
            severity_rank.get(str(f.get("severity", "")).lower(), 0),
            confidence_rank.get(str(f.get("confidence", "")).lower(), 0),
        ), reverse=True)

        primary = dict(group[0])  # Copy the best representative

        # Collect all affected endpoints
        endpoints: list[dict[str, str | None]] = []
        all_evidence_parts: list[str] = []
        for f in group:
            url = f.get("affected_url") or f.get("url")
            endpoints.append({
                "url": url,
                "method": f.get("method"),
                "parameter": f.get("affected_parameter") or f.get("parameter"),
                "source_module": f.get("source_module"),
            })
            ev = f.get("evidence")
            if ev and ev not in all_evidence_parts:
                all_evidence_parts.append(str(ev))

        # Store grouped endpoints in metadata
        meta = primary.get("metadata_json") or {}
        meta["grouped_endpoints"] = endpoints
        meta["endpoint_count"] = len(endpoints)
        meta["correlation_key"] = corr_key
        primary["metadata_json"] = meta

        # Merge evidence — include all unique evidence blocks
        if len(all_evidence_parts) > 1:
            merged_evidence = "\n\n---\n\n".join(all_evidence_parts[:10])
            if len(all_evidence_parts) > 10:
                merged_evidence += f"\n\n... and {len(all_evidence_parts) - 10} more endpoints"
            primary["evidence"] = merged_evidence

        # Set correlation key on the primary finding
        primary["correlation_key"] = corr_key

        return primary

    @property
    def rejected_count(self) -> int:
        return len(self._rejected)

    @property
    def group_count(self) -> int:
        return len(self._groups)

    @property
    def merged_count(self) -> int:
        return sum(1 for g in self._groups.values() if len(g) > 1)
