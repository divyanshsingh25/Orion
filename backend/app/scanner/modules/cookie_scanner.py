"""Cookie security scanner module.

Checks each cookie for Secure, HttpOnly, SameSite flags.
Stores actual Set-Cookie evidence.
"""

from __future__ import annotations

from typing import Any


def scan_cookies(cookies: list[dict[str, Any]], target_url: str) -> list[dict[str, Any]]:
    """Analyze cookies for security flag issues.

    Parameters
    ----------
    cookies
        List of cookie dicts (from aiohttp response parsing or recon).
    target_url
        The target URL for evidence context.

    Returns
    -------
    list[dict]
        Findings for cookies with missing security flags.
    """

    findings: list[dict[str, Any]] = []
    is_https = target_url.startswith("https://")

    for cookie in cookies:
        name = cookie.get("name", "unknown")
        issues: list[str] = []
        evidence_parts: list[str] = [f"Cookie: {name}"]

        # --- Secure flag ---
        secure = cookie.get("secure", False)
        if is_https and not secure:
            issues.append("Secure flag missing")
            evidence_parts.append("Secure=absent")

        # --- HttpOnly flag ---
        httponly = cookie.get("httponly", False)
        if not httponly:
            issues.append("HttpOnly flag missing")
            evidence_parts.append("HttpOnly=absent")

        # --- SameSite flag ---
        samesite = cookie.get("samesite", "")
        if not samesite or samesite.lower() == "none":
            if not samesite:
                issues.append("SameSite attribute missing")
                evidence_parts.append("SameSite=absent")
            elif samesite.lower() == "none":
                issues.append("SameSite set to None")
                evidence_parts.append("SameSite=None")

        if not issues:
            continue

        # Determine severity based on cookie characteristics
        is_session_cookie = _is_session_cookie(name)
        if is_session_cookie:
            if "HttpOnly flag missing" in issues:
                severity = "Medium"
                cvss = 5.4
            elif "Secure flag missing" in issues:
                severity = "Medium"
                cvss = 5.0
            else:
                severity = "Low"
                cvss = 3.1
        else:
            severity = "Low"
            cvss = 2.6

        # Build evidence string
        evidence_parts.append(f"Domain={cookie.get('domain', 'N/A')}")
        evidence_parts.append(f"Path={cookie.get('path', '/')}")
        evidence = "; ".join(evidence_parts)

        findings.append({
            "title": f"Cookie '{name}' — {', '.join(issues)}",
            "description": (
                f"The cookie '{name}' is missing security attributes: {', '.join(issues)}. "
                f"This may allow cookie theft, session hijacking, or CSRF attacks."
            ),
            "finding_type": "cookie_security",
            "severity": severity,
            "cvss": cvss,
            "confidence": "High",
            "evidence": evidence,
            "affected_url": target_url,
            "parameter": name,
            "remediation": _cookie_remediation(issues),
            "cwe": "CWE-614" if "Secure flag missing" in issues else "CWE-1004",
            "owasp": "A05:2021 - Security Misconfiguration",
        })

    return findings


def _is_session_cookie(name: str) -> bool:
    """Heuristic: is this likely a session / auth cookie?"""
    name_lower = name.lower()
    session_patterns = [
        "session", "sess", "sid", "ssid", "token",
        "auth", "jwt", "csrf", "xsrf", "phpsessid",
        "jsessionid", "connect.sid", "laravel_session",
        "asp.net_sessionid", "_session", "sessionid",
    ]
    return any(p in name_lower for p in session_patterns)


def _cookie_remediation(issues: list[str]) -> str:
    parts = []
    if "Secure flag missing" in issues:
        parts.append("Add the Secure flag to ensure the cookie is only sent over HTTPS.")
    if "HttpOnly flag missing" in issues:
        parts.append("Add the HttpOnly flag to prevent JavaScript access to the cookie.")
    if "SameSite attribute missing" in issues or "SameSite set to None" in issues:
        parts.append("Set SameSite=Lax or SameSite=Strict to mitigate CSRF attacks.")
    return " ".join(parts)
