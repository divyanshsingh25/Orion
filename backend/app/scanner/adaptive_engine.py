"""ORION Adaptive Scanning Engine.

Analyzes findings from an initial scan pass and recommends follow-up tests
based on vulnerability patterns and relationships.

Example chains:
  - SQLi found → test for RCE via SQL
  - XSS found → test for CSRF on same forms
  - SSRF found → test for RCE via SSRF chains
  - Open Redirect → test for XSS via redirect
  - Missing auth → test IDOR/BOLA more aggressively
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("orion.adaptive")

# Maximum number of adaptive rounds to prevent infinite loops
MAX_ADAPTIVE_ROUNDS = 2

# Vulnerability chains: finding_type → list of follow-up modules + context
_CHAINS: dict[str, list[dict[str, Any]]] = {
    "sqli": [
        {"module": "rce", "reason": "SQL injection may enable command execution via xp_cmdshell, LOAD_FILE, etc."},
        {"module": "lfi", "reason": "SQL injection may enable file read via LOAD_FILE or INTO OUTFILE."},
    ],
    "xss": [
        {"module": "csrf", "reason": "XSS can bypass CSRF protections; testing CSRF on forms with reflected XSS."},
        {"module": "open_redirect", "reason": "XSS context may enable redirect-based attacks."},
    ],
    "ssrf": [
        {"module": "rce", "reason": "SSRF may enable RCE via internal service exploitation."},
        {"module": "lfi", "reason": "SSRF via file:// protocol may enable local file inclusion."},
    ],
    "open_redirect": [
        {"module": "xss", "reason": "Open redirect may be leverageable for reflected XSS via javascript: URIs."},
        {"module": "ssrf", "reason": "Redirect endpoints may accept internal URLs for SSRF."},
    ],
    "cors": [
        {"module": "csrf", "reason": "Permissive CORS may weaken CSRF protections."},
        {"module": "idor", "reason": "CORS misconfiguration may enable cross-origin data access."},
    ],
    "security_headers": [
        {"module": "xss", "reason": "Missing CSP or X-XSS-Protection may make XSS more exploitable."},
        {"module": "cors", "reason": "Missing security headers often correlate with CORS misconfigurations."},
    ],
    "idor": [
        {"module": "sqli", "reason": "IDOR parameters may also be injectable."},
        {"module": "path_traversal", "reason": "Resource identifiers may be vulnerable to path traversal."},
    ],
    "lfi": [
        {"module": "rce", "reason": "LFI via log poisoning or PHP wrappers may enable RCE."},
        {"module": "path_traversal", "reason": "LFI context should be tested for deeper path traversal."},
    ],
    "ssti": [
        {"module": "rce", "reason": "SSTI almost always leads to RCE; verify with direct command execution."},
    ],
    "xxe": [
        {"module": "ssrf", "reason": "XXE can be used for SSRF via external entity requests."},
        {"module": "lfi", "reason": "XXE can read local files via file:// entities."},
    ],
    "jwt_weakness": [
        {"module": "idor", "reason": "JWT weaknesses may allow authorization bypass for IDOR testing."},
    ],
    "cookie_security": [
        {"module": "csrf", "reason": "Insecure cookies may make CSRF attacks more effective."},
        {"module": "xss", "reason": "Cookies without HttpOnly flag are exfiltrable via XSS."},
    ],
}


class AdaptiveEngine:
    """Analyzes scan findings to recommend follow-up tests."""

    def __init__(self, available_modules: set[str]) -> None:
        self.available_modules = available_modules

    def recommend(
        self,
        findings: list[dict[str, Any]],
        already_run: set[str],
        round_number: int = 1,
    ) -> list[dict[str, Any]]:
        """Recommend follow-up scanner modules based on current findings.

        Args:
            findings: Current list of findings.
            already_run: Set of module names already executed.
            round_number: Current adaptive round (1-based).

        Returns:
            List of ``{"module": str, "reason": str, "target_urls": list}``
            recommendations.
        """
        if round_number > MAX_ADAPTIVE_ROUNDS:
            logger.info("Adaptive scanning: max rounds (%d) reached", MAX_ADAPTIVE_ROUNDS)
            return []

        recommendations: list[dict[str, Any]] = []
        recommended_modules: set[str] = set()

        # Collect findings by type
        findings_by_type: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            ftype = f.get("finding_type") or f.get("type", "")
            findings_by_type.setdefault(ftype, []).append(f)

        # Check severity distribution for targeted follow-ups
        high_severity_types: set[str] = set()
        for f in findings:
            sev = (f.get("severity") or "").lower()
            if sev in ("critical", "high"):
                ftype = f.get("finding_type") or f.get("type", "")
                high_severity_types.add(ftype)

        # Apply chains
        for finding_type, type_findings in findings_by_type.items():
            chains = _CHAINS.get(finding_type, [])
            for chain in chains:
                module = chain["module"]
                reason = chain["reason"]

                # Skip if already run or not available
                if module in already_run or module in recommended_modules:
                    continue
                if module not in self.available_modules:
                    continue

                # Collect target URLs from the triggering findings
                target_urls = []
                for f in type_findings:
                    url = f.get("affected_url") or f.get("url", "")
                    if url and url not in target_urls:
                        target_urls.append(url)

                recommendations.append({
                    "module": module,
                    "reason": f"[Adaptive] {reason} (triggered by {len(type_findings)} {finding_type} finding(s))",
                    "target_urls": target_urls[:10],  # Limit target URLs
                    "priority": "high" if finding_type in high_severity_types else "normal",
                    "triggered_by": finding_type,
                    "round": round_number,
                })
                recommended_modules.add(module)

                logger.info(
                    "Adaptive round %d: recommending %s (triggered by %s, %d targets)",
                    round_number, module, finding_type, len(target_urls),
                )

        return recommendations

    def summarize_adaptive_results(
        self,
        recommendations: list[dict[str, Any]],
        additional_findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Summarize what the adaptive engine did."""
        return {
            "rounds_completed": max((r.get("round", 0) for r in recommendations), default=0),
            "modules_recommended": len(recommendations),
            "modules_run": [r["module"] for r in recommendations],
            "additional_findings": len(additional_findings),
            "chains_triggered": list({r["triggered_by"] for r in recommendations}),
        }
