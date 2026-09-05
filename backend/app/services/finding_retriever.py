"""ORION Finding Retriever for AI Chat.

Retrieval pipeline:
  1. Extract keywords and intent from user question
  2. Query relevant findings from the database
  3. Format findings into compact context for the LLM

This is NOT a full-scan dump.  Only the findings relevant to the
user's question are retrieved, keeping the LLM context small and focused.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.models import AIAnalysis, Finding, Project, Scan

logger = logging.getLogger("orion.retriever")

# Maps natural language terms to finding_type / severity values
_TYPE_KEYWORDS: dict[str, list[str]] = {
    "xss": ["xss", "cross-site scripting", "cross site scripting", "script injection"],
    "sqli": ["sql injection", "sqli", "sql", "database injection"],
    "csrf": ["csrf", "cross-site request forgery", "cross site request forgery"],
    "ssrf": ["ssrf", "server-side request forgery", "server side request forgery"],
    "rce": ["rce", "remote code execution", "command injection", "code execution"],
    "lfi": ["lfi", "local file inclusion", "file inclusion"],
    "path_traversal": ["path traversal", "directory traversal", "dot dot"],
    "xxe": ["xxe", "xml external entity", "xml injection"],
    "idor": ["idor", "bola", "broken object", "insecure direct object"],
    "open_redirect": ["open redirect", "url redirect", "redirect"],
    "cors": ["cors", "cross-origin", "cross origin"],
    "nosqli": ["nosql injection", "nosqli", "nosql", "mongodb injection"],
    "ldapi": ["ldap injection", "ldapi", "ldap"],
    "ssti": ["ssti", "template injection", "server-side template"],
    "security_headers": ["security headers", "headers", "csp", "hsts", "x-frame"],
    "cookie_security": ["cookie", "session cookie", "httponly", "secure flag"],
    "jwt_weakness": ["jwt", "json web token", "token", "bearer"],
    "tls_misconfiguration": ["tls", "ssl", "certificate", "https", "cipher"],
    "api_security": ["api", "rest api", "api security", "endpoint"],
    "graphql_security": ["graphql", "gql", "introspection"],
    "service_vulnerability": ["cve", "vulnerability", "outdated", "known vulnerability"],
}

_SEVERITY_KEYWORDS: dict[str, list[str]] = {
    "critical": ["critical", "crit", "highest", "most severe", "most dangerous"],
    "high": ["high", "serious", "severe", "important"],
    "medium": ["medium", "moderate", "mid"],
    "low": ["low", "minor", "informational", "info"],
}

# Intent patterns
_GENERAL_INTENTS = [
    "summary", "overview", "risk", "status", "what's wrong",
    "how many", "total", "count", "how secure", "security posture",
    "top", "worst", "most dangerous", "biggest risk", "prioritize",
]


class FindingRetriever:
    """Retrieves relevant findings from the database based on a user question."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def retrieve(
        self,
        question: str,
        user_id: str,
        *,
        scan_id: str | None = None,
        max_results: int = 10,
    ) -> dict[str, Any]:
        """Retrieve findings relevant to the user's question.

        Returns:
            {
                "findings": [...],  # List of finding dicts with evidence
                "summary": {...},   # Severity counts and stats
                "query_type": str,  # "specific" or "general"
            }
        """
        intent = self._classify_intent(question)
        types = self._extract_types(question)
        severities = self._extract_severities(question)
        cwe_ids = self._extract_cwe_ids(question)
        urls = self._extract_urls(question)

        # Build query
        query = (
            select(Finding)
            .join(Finding.project)
            .where(Project.user_id == user_id)
        )

        if scan_id:
            query = query.where(Finding.scan_id == scan_id)

        filters = []
        if types:
            filters.append(Finding.finding_type.in_(types))
        if severities:
            filters.append(func.lower(Finding.severity).in_(severities))
        if cwe_ids:
            filters.append(Finding.cwe_id.in_(cwe_ids))
        if urls:
            url_conditions = [Finding.affected_url.contains(u) for u in urls]
            filters.append(or_(*url_conditions))

        if filters:
            query = query.where(and_(*filters))

        # If general intent and no specific filters, get top findings by severity
        if intent == "general" and not filters:
            query = query.order_by(
                # Sort by severity priority
                func.case(
                    (func.lower(Finding.severity) == "critical", 0),
                    (func.lower(Finding.severity) == "high", 1),
                    (func.lower(Finding.severity) == "medium", 2),
                    (func.lower(Finding.severity) == "low", 3),
                    else_=4,
                )
            )
        else:
            query = query.order_by(Finding.created_at.desc())

        query = query.limit(max_results)
        result = await self.db.execute(query)
        findings = list(result.scalars().all())

        # Also get severity summary
        summary = await self._get_summary(user_id, scan_id)

        # Format findings
        formatted = [self._format_finding(f) for f in findings]

        return {
            "findings": formatted,
            "summary": summary,
            "query_type": intent,
            "filters_applied": {
                "types": types,
                "severities": severities,
                "cwe_ids": cwe_ids,
                "urls": urls,
                "scan_id": scan_id,
            },
        }

    def _classify_intent(self, question: str) -> str:
        """Classify whether the question is general or specific."""
        q = question.lower()
        if any(intent in q for intent in _GENERAL_INTENTS):
            return "general"
        return "specific"

    def _extract_types(self, question: str) -> list[str]:
        """Extract vulnerability types mentioned in the question."""
        q = question.lower()
        found: list[str] = []
        for ftype, keywords in _TYPE_KEYWORDS.items():
            for kw in keywords:
                if kw in q:
                    if ftype not in found:
                        found.append(ftype)
                    break
        return found

    def _extract_severities(self, question: str) -> list[str]:
        """Extract severity levels mentioned in the question."""
        q = question.lower()
        found: list[str] = []
        for severity, keywords in _SEVERITY_KEYWORDS.items():
            for kw in keywords:
                if kw in q:
                    if severity not in found:
                        found.append(severity)
                    break
        return found

    def _extract_cwe_ids(self, question: str) -> list[str]:
        """Extract CWE IDs mentioned in the question."""
        return re.findall(r"CWE-\d+", question, re.I)

    def _extract_urls(self, question: str) -> list[str]:
        """Extract URL fragments mentioned in the question."""
        # Match URLs or path patterns
        urls = re.findall(r"https?://\S+", question)
        # Also match path patterns like /api/users
        paths = re.findall(r"(?<!\w)/\w[\w/.-]+", question)
        return urls + paths

    async def _get_summary(self, user_id: str, scan_id: str | None) -> dict[str, Any]:
        """Get severity summary counts."""
        query = (
            select(
                func.lower(Finding.severity).label("severity"),
                func.count().label("count"),
            )
            .join(Finding.project)
            .where(Project.user_id == user_id)
        )
        if scan_id:
            query = query.where(Finding.scan_id == scan_id)

        query = query.group_by(func.lower(Finding.severity))
        result = await self.db.execute(query)
        rows = result.all()

        summary = {"total": 0}
        for row in rows:
            summary[row.severity] = row.count
            summary["total"] += row.count

        return summary

    def _format_finding(self, finding: Finding) -> dict[str, Any]:
        """Format a Finding model into a compact dict for the LLM context."""
        return {
            "id": finding.id,
            "title": finding.title,
            "type": finding.finding_type,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "affected_url": finding.affected_url,
            "affected_parameter": finding.affected_parameter,
            "evidence": (finding.evidence or "")[:500],  # Truncate for context window
            "cwe_id": finding.cwe_id,
            "cwe_name": finding.cwe_name,
            "owasp": finding.owasp_category,
            "cvss_score": float(finding.cvss_score),
            "remediation": finding.remediation[:300] if finding.remediation else "",
            "status": finding.status,
            "lifecycle": getattr(finding, "lifecycle_status", None) or "unknown",
        }


def format_findings_context(retrieval_result: dict[str, Any]) -> str:
    """Format retrieved findings into a compact text block for the LLM.

    This is what gets injected as context — NOT the full scan data.
    """
    findings = retrieval_result.get("findings", [])
    summary = retrieval_result.get("summary", {})
    filters = retrieval_result.get("filters_applied", {})

    parts: list[str] = []

    # Summary header
    total = summary.get("total", 0)
    if total > 0:
        parts.append("=== ORION Scan Data (Retrieved Findings) ===")
        parts.append(f"Total findings across scans: {total}")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = summary.get(sev, 0)
            if count:
                parts.append(f"  {sev.title()}: {count}")
        parts.append("")
    else:
        parts.append("=== ORION Scan Data ===")
        parts.append("No findings match the query.")
        return "\n".join(parts)

    # Individual findings
    if findings:
        parts.append(f"--- {len(findings)} Relevant Finding(s) ---")
        for i, f in enumerate(findings, 1):
            parts.append(f"\n[Finding {i}] {f['title']}")
            parts.append(f"  ID: {f['id']}")
            parts.append(f"  Severity: {f['severity']} | Confidence: {f['confidence']} | CVSS: {f['cvss_score']}")
            parts.append(f"  Type: {f['type']} | CWE: {f['cwe_id']} ({f['cwe_name']})")
            parts.append(f"  OWASP: {f['owasp']}")
            if f.get("affected_url"):
                parts.append(f"  URL: {f['affected_url']}")
            if f.get("affected_parameter"):
                parts.append(f"  Parameter: {f['affected_parameter']}")
            if f.get("evidence"):
                parts.append(f"  Evidence: {f['evidence']}")
            if f.get("remediation"):
                parts.append(f"  Remediation: {f['remediation']}")
            if f.get("lifecycle") and f["lifecycle"] != "unknown":
                parts.append(f"  Status: {f['lifecycle']}")
    else:
        parts.append("No findings matched the specific query filters.")

    parts.append("\n=== End of ORION Data ===")
    return "\n".join(parts)
