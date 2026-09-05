from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskProfile:
    owasp: str
    cwe: str
    cwe_name: str
    cvss_score: float
    cvss_vector: str
    severity: str
    confidence: str
    risk_rating: str


RISK_MAP: dict[str, RiskProfile] = {
    "xss": RiskProfile("A03:2021 - Injection", "CWE-79", "Cross-site Scripting", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium", "High", "Medium"),
    "sqli": RiskProfile("A03:2021 - Injection", "CWE-89", "SQL Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "High", "Critical"),
    "csrf": RiskProfile("A01:2021 - Broken Access Control", "CWE-352", "Cross-Site Request Forgery", 5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "Medium", "Medium", "Medium"),
    "ssrf": RiskProfile("A10:2021 - Server-Side Request Forgery", "CWE-918", "Server-Side Request Forgery", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", "High", "High", "High"),
    "lfi": RiskProfile("A03:2021 - Injection", "CWE-22", "Path Traversal", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", "High", "High", "High"),
    "path_traversal": RiskProfile("A03:2021 - Injection", "CWE-22", "Path Traversal", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", "High", "High", "High"),
    "xxe": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-611", "XML External Entity", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "High", "High", "High"),
    "rce": RiskProfile("A03:2021 - Injection", "CWE-94", "Code Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "High", "Critical"),
    "idor": RiskProfile("A01:2021 - Broken Access Control", "CWE-639", "Authorization Bypass Through User-Controlled Key", 8.6, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L", "High", "High", "High"),
    "open_redirect": RiskProfile("A01:2021 - Broken Access Control", "CWE-601", "Open Redirect", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium", "Medium", "Medium"),
    "cors": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-942", "Permissive CORS Policy", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "Medium", "Medium", "Medium"),
    "nosqli": RiskProfile("A03:2021 - Injection", "CWE-943", "NoSQL Injection", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", "High", "High", "High"),
    "ldapi": RiskProfile("A03:2021 - Injection", "CWE-90", "LDAP Injection", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", "High", "High", "High"),
    "ssti": RiskProfile("A03:2021 - Injection", "CWE-94", "Server-Side Template Injection", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "High", "Critical"),
    "security_headers": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-693", "Protection Mechanism Failure", 3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "Low", "High", "Low"),
    "information_disclosure": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-200", "Exposure of Sensitive Information", 3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Low", "Medium", "Low"),
    "directory_discovery": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-548", "Information Exposure Through Directory Listing", 4.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium", "Medium", "Medium"),
    "sensitive_file": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-200", "Sensitive Information Exposure", 5.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Medium", "Medium", "Medium"),
    # --- New profiles for added modules ---
    "cookie_security": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-614", "Sensitive Cookie Without Secure Flag", 3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "Low", "High", "Low"),
    "service_vulnerability": RiskProfile("A06:2021 - Vulnerable and Outdated Components", "CWE-1035", "Using Known Vulnerable Components", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High", "Medium", "High"),
    "port_exposure": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-200", "Unnecessary Open Port", 3.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Low", "Medium", "Low"),
    "dns_info": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-200", "DNS Information Disclosure", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "Info", "High", "Info"),
    "whois_info": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-200", "WHOIS Information Disclosure", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "Info", "High", "Info"),
    "os_detection": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-200", "OS Fingerprint Detected", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "Info", "Medium", "Info"),
    # --- Phase 4/5 profiles ---
    "api_security": RiskProfile("A01:2021 - Broken Access Control", "CWE-284", "Improper Access Control", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "Medium", "Medium", "Medium"),
    "graphql_security": RiskProfile("A05:2021 - Security Misconfiguration", "CWE-200", "GraphQL Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium", "High", "Medium"),
    "bola": RiskProfile("A01:2021 - Broken Access Control", "CWE-639", "Broken Object-Level Authorization", 8.6, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L", "High", "High", "High"),
    "mass_assignment": RiskProfile("A04:2021 - Insecure Design", "CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", "Medium", "Medium", "Medium"),
    "jwt_weakness": RiskProfile("A02:2021 - Cryptographic Failures", "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High", "High", "High"),
    "tls_misconfiguration": RiskProfile("A02:2021 - Cryptographic Failures", "CWE-326", "Inadequate Encryption Strength", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium", "High", "Medium"),
}


def lookup_profile(finding_type: str) -> RiskProfile:
    return RISK_MAP.get(finding_type, RiskProfile("A05:2021 - Security Misconfiguration", "CWE-200", "Information Exposure", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "Low", "Medium", "Low"))


def severity_from_cvss(cvss: float) -> str:
    """Convert a CVSS score to a severity string — THE source of truth."""
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0.0:
        return "Low"
    return "Info"


# CVSS v3.1 metric value weights for dynamic vector reconstruction
_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_PR_WEIGHTS_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHTS_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}
_S_VALUES = {"U": False, "C": True}


def _parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS:3.1 vector string into a dict of metric → value."""
    parts = vector.replace("CVSS:3.1/", "").split("/")
    return {p.split(":")[0]: p.split(":")[1] for p in parts if ":" in p}


def _build_vector(metrics: dict[str, str]) -> str:
    """Reconstruct a CVSS:3.1 vector string from metric dict."""
    order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    parts = [f"{m}:{metrics.get(m, 'N')}" for m in order if m in metrics]
    return "CVSS:3.1/" + "/".join(parts)


def calculate_dynamic_cvss(finding: dict) -> tuple[float, str, str]:
    """Calculate CVSS score, severity, and vector dynamically from finding data.

    This is the CENTRAL severity calculation — all findings flow through here.
    The function uses the finding's own ``cvss`` value when present and sensible,
    otherwise falls back to the profile for that finding type.  In all cases,
    severity is re-derived from the final numeric score so they ALWAYS agree.

    Context-aware adjustments:
      - confidence: low → -1.0, confirmed → +0.5
      - auth_required: True → reduce score (attacker needs privileges)
      - user_interaction: True → reduce score (requires user action)
      - scope_change: True → increase score (impacts other components)
      - sensitive_data: True → increase score (PII, credentials involved)
      - internal_only: True → reduce score (not network-accessible)

    Returns ``(cvss_score, severity, cvss_vector)``.
    """

    finding_type = str(finding.get("finding_type") or finding.get("type") or "information_disclosure")
    profile = lookup_profile(finding_type)

    # --- 1. Determine base CVSS ---
    raw_cvss = finding.get("cvss")
    if raw_cvss is not None:
        try:
            cvss = float(raw_cvss)
        except (TypeError, ValueError):
            cvss = profile.cvss_score
    else:
        cvss = profile.cvss_score

    # --- 2. Parse and adjust CVSS vector based on context ---
    base_vector = str(finding.get("cvss_vector") or profile.cvss_vector)
    metrics = _parse_vector(base_vector)

    # Context adjustments
    auth_required = finding.get("auth_required") or finding.get("requires_auth")
    if auth_required:
        metrics["PR"] = "L"  # Requires low privileges
        cvss = max(0.0, cvss - 1.0)

    user_interaction = finding.get("user_interaction") or finding.get("requires_interaction")
    if user_interaction:
        metrics["UI"] = "R"  # Requires user interaction
        cvss = max(0.0, cvss - 0.5)

    scope_change = finding.get("scope_change") or finding.get("crosses_boundary")
    if scope_change:
        metrics["S"] = "C"  # Changed scope
        cvss = min(10.0, cvss + 0.5)

    sensitive_data = finding.get("sensitive_data") or finding.get("pii_involved")
    if sensitive_data:
        metrics["C"] = "H"  # High confidentiality impact
        cvss = min(10.0, cvss + 0.5)

    internal_only = finding.get("internal_only")
    if internal_only:
        metrics["AV"] = "A"  # Adjacent network only
        cvss = max(0.0, cvss - 1.5)

    # --- 3. Adjust based on confidence ---
    confidence = str(finding.get("confidence") or "Medium").lower()
    if confidence == "low":
        cvss = max(0.0, cvss - 1.0)
    elif confidence == "confirmed":
        cvss = min(10.0, cvss + 0.5)

    cvss = round(min(10.0, max(0.0, cvss)), 1)

    # --- 4. Derive severity from final CVSS so they ALWAYS match ---
    severity = severity_from_cvss(cvss)

    # --- 5. Rebuild vector ---
    vector = _build_vector(metrics)

    return cvss, severity, vector
