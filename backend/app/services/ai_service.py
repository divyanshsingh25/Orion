from __future__ import annotations

from typing import Any

from app.core.owasp import lookup_profile


class AIService:
    def generate_finding_analysis(self, finding: dict[str, Any]) -> dict[str, Any]:
        from app.services.deterministic_verifier import DeterministicVerifier
        profile = lookup_profile(str(finding.get("finding_type", finding.get("type", "information_disclosure"))))
        title = str(finding.get("title") or finding.get("description") or profile.cwe_name)
        remediation = str(finding.get("remediation") or "Review and remediate the vulnerable code path.")
        
        # Run deterministic verification baseline
        det_verdict = DeterministicVerifier.verify(finding)

        return {
            "simple_explanation": self._simple_explanation(title, finding),
            "technical_explanation": self._technical_explanation(finding),
            "business_impact": self._business_impact(profile, finding),
            "risk_explanation": self._risk_explanation(profile, finding),
            "owasp_explanation": f"This issue maps to {profile.owasp} because it weakens controls associated with {profile.cwe_name}.",
            "cwe_explanation": f"{profile.cwe} describes {profile.cwe_name}, which is directly relevant to the observed behavior.",
            "remediation_steps_json": self._remediation_steps(finding, remediation),
            "best_practices_json": self._best_practices(finding),
            "secure_coding_recommendation": self._secure_coding_recommendation(finding),
            "verification_guidance": self._verification_guidance(finding),
            "code_example": self._code_example(finding),
            "references_json": self._references(profile),
            "generated_by": "orion-ai-engine",
            "verification_verdict": det_verdict["verdict"],
            "verification_reasoning": det_verdict["reasoning"],
            "verification_confidence": det_verdict["confidence"],
        }

    def _simple_explanation(self, title: str, finding: dict[str, Any]) -> str:
        return f"{title} was identified on {finding.get('affected_url', 'the target application')}. The issue can expose sensitive behavior or weaken a defensive control."

    def _technical_explanation(self, finding: dict[str, Any]) -> str:
        evidence = finding.get("evidence") or "scan evidence"
        return f"The scanner observed {evidence}. The finding is reproducible at {finding.get('affected_url', 'the affected endpoint')} and should be treated as a concrete, actionable weakness."

    def _business_impact(self, profile, finding: dict[str, Any]) -> str:
        if profile.severity == "Critical":
            return "An attacker could gain unauthorized access, tamper with sensitive data, or materially disrupt business operations."
        if profile.severity == "High":
            return "This issue can expose protected data, undermine trust, and increase the likelihood of account or data compromise."
        if profile.severity == "Medium":
            return "This weakness increases attack surface and may be combined with other flaws to escalate impact."
        return "The issue is lower severity, but it still discloses information or reduces security margin."

    def _risk_explanation(self, profile, finding: dict[str, Any]) -> str:
        return f"Risk is rated {profile.risk_rating} because the issue is reachable through the application interface and may be exploited with limited prerequisites."

    def _remediation_steps(self, finding: dict[str, Any], remediation: str) -> list[str]:
        steps = [
            "Locate the code path, configuration, or infrastructure control that produced the finding.",
            remediation,
            "Add regression tests so the issue does not reappear in future releases.",
        ]
        return steps

    def _best_practices(self, finding: dict[str, Any]) -> list[str]:
        return [
            "Validate and normalize inputs at the trust boundary.",
            "Apply least privilege and explicit allowlists.",
            "Log security-sensitive events and monitor for anomalies.",
        ]

    def _secure_coding_recommendation(self, finding: dict[str, Any]) -> str:
        return "Prefer framework-provided safe APIs, avoid string concatenation for security-sensitive operations, and encode output for the correct execution context."

    def _verification_guidance(self, finding: dict[str, Any]) -> str:
        return "Re-scan the same endpoint and parameter set after remediation, confirm the response no longer matches the proof of concept, and attach the evidence to the ticket."

    def _code_example(self, finding: dict[str, Any]) -> str | None:
        finding_type = str(finding.get("finding_type", ""))
        if finding_type == "sqli":
            return "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
        if finding_type == "xss":
            return "return html.escape(user_supplied_value, quote=True)"
        if finding_type == "open_redirect":
            return "if target not in allowed_redirects: raise ValueError(\"Invalid redirect target\")"
        return None

    def _references(self, profile) -> list[dict[str, str]]:
        return [
            {"title": "OWASP Top 10", "url": "https://owasp.org/Top10/"},
            {"title": "CWE Entry", "url": f"https://cwe.mitre.org/data/definitions/{profile.cwe.split('-')[-1]}.html"},
        ]
