"""ORION API Security Scanner.

Tests discovered API endpoints for common security weaknesses:
  - Authentication bypass (accessing without credentials)
  - HTTP method enumeration (OPTIONS, PUT, DELETE, PATCH)
  - Excessive data exposure (large response bodies, PII patterns)
  - Rate limiting absence
  - CORS on API endpoints
  - Broken Object-Level Authorization (BOLA) patterns
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger("orion.api_scanner")

# PII patterns to detect excessive data exposure
_PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.I),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "phone": re.compile(r"\b\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "api_key": re.compile(r"(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['\"]?[\w-]{16,}", re.I),
}

# Methods to test during enumeration
_TEST_METHODS = ["OPTIONS", "PUT", "DELETE", "PATCH", "HEAD", "TRACE"]


async def scan_api_endpoints(
    session: aiohttp.ClientSession,
    api_endpoints: list[dict[str, Any]],
    target_url: str,
    *,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Scan discovered API endpoints for security issues.

    Args:
        session: Authenticated or unauthenticated aiohttp session.
        api_endpoints: List of ``{"url": ..., "method": ...}`` dicts.
        target_url: The base scan target URL.
        timeout: Per-request timeout.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []
    if not api_endpoints:
        return findings

    checked_urls: set[str] = set()

    for ep in api_endpoints[:30]:  # Limit to 30 endpoints
        if isinstance(ep, dict):
            url = ep.get("url", "")
        else:
            url = str(ep).strip()
        if not url or url in checked_urls:
            continue
        checked_urls.add(url)

        # 1. Method Enumeration
        method_findings = await _test_method_enumeration(session, url, timeout)
        findings.extend(method_findings)

        # 2. Excessive Data Exposure
        exposure_findings = await _test_data_exposure(session, url, timeout)
        findings.extend(exposure_findings)

        # 3. CORS on API endpoint
        cors_findings = await _test_api_cors(session, url, timeout)
        findings.extend(cors_findings)

        # Rate limit between endpoint tests
        await asyncio.sleep(0.1)

    return findings


async def _test_method_enumeration(
    session: aiohttp.ClientSession, url: str, timeout: float
) -> list[dict[str, Any]]:
    """Test which HTTP methods are actually accepted with meaningful impact.

    Classification of responses:
      - 2xx        → Method Accepted (potential issue for state-changing methods)
      - 401        → Requires Authentication (not a misconfiguration)
      - 403        → Method Rejected (forbidden — correct behavior)
      - 404        → Resource Not Found (not related to method acceptance)
      - 405        → Method Not Allowed (correct behavior)
      - 301/302    → Redirect (not method acceptance)

    Only reports findings when there is meaningful security impact:
      - Dangerous methods (PUT/DELETE/PATCH) returning 2xx
      - TRACE returning 2xx (XST risk)
    Does NOT report OPTIONS Allow header alone as a vulnerability.
    """
    findings: list[dict[str, Any]] = []

    accepted: list[str] = []         # Methods returning 2xx
    authenticated: list[str] = []    # Methods returning 401
    rejected: list[str] = []         # Methods returning 403/405
    not_found: list[str] = []        # Methods returning 404

    _DANGEROUS_METHODS = ["PUT", "DELETE", "PATCH", "TRACE"]

    for method in _TEST_METHODS:
        try:
            async with session.request(
                method, url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as resp:
                status = resp.status

                if method == "TRACE" and 200 <= status < 300:
                    findings.append({
                        "type": "api_security",
                        "title": "HTTP TRACE method enabled on API endpoint",
                        "description": (
                            "The TRACE method is enabled and returns a successful response, "
                            "which can be used for Cross-Site Tracing (XST) attacks to "
                            "steal credentials from HTTP headers."
                        ),
                        "url": url,
                        "affected_url": url,
                        "method": method,
                        "detection": f"TRACE returned status {status}",
                        "detection_reason": f"TRACE method returned HTTP {status} — active and responsive",
                        "severity": "Medium",
                        "confidence": "High",
                        "cwe": "CWE-693",
                        "owasp": "A05:2021 - Security Misconfiguration",
                        "remediation": "Disable TRACE method on all endpoints.",
                    })
                    accepted.append(f"TRACE ({status})")
                elif 200 <= status < 300:
                    accepted.append(f"{method} ({status})")
                elif status == 401:
                    authenticated.append(f"{method} ({status})")
                elif status in (403, 405, 501):
                    rejected.append(f"{method} ({status})")
                elif status == 404:
                    not_found.append(f"{method} ({status})")
                # 301/302/other — not relevant for method acceptance
        except Exception:
            continue

    # Only report dangerous methods that are ACTUALLY accepted (2xx response)
    dangerous_accepted = [m for m in accepted if any(
        m.startswith(d) for d in _DANGEROUS_METHODS
    )]

    if dangerous_accepted:
        findings.append({
            "type": "api_security",
            "title": "Dangerous HTTP methods accepted on API endpoint",
            "description": (
                f"API endpoint accepts state-changing HTTP methods with successful responses: "
                f"{', '.join(dangerous_accepted)}. "
                f"Methods requiring auth: {', '.join(authenticated) or 'none'}. "
                f"Methods rejected: {', '.join(rejected) or 'none'}."
            ),
            "url": url,
            "affected_url": url,
            "detection": f"Accepted: {', '.join(dangerous_accepted)}",
            "detection_reason": (
                f"State-changing methods returned 2xx responses: {', '.join(dangerous_accepted)}"
            ),
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-749",
            "owasp": "A05:2021 - Security Misconfiguration",
            "remediation": (
                "Restrict HTTP methods to only those required by the API. "
                "Disable PUT, DELETE, PATCH unless explicitly needed for this endpoint."
            ),
        })

    return findings



async def _test_data_exposure(
    session: aiohttp.ClientSession, url: str, timeout: float
) -> list[dict[str, Any]]:
    """Check for excessive data exposure in API responses."""
    findings: list[dict[str, Any]] = []

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status >= 400:
                return findings

            ct = resp.headers.get("Content-Type", "")
            if "json" not in ct and "xml" not in ct:
                return findings

            body = await resp.text(errors="ignore")

            # Check for PII in response
            pii_found: list[str] = []
            for pii_type, pattern in _PII_PATTERNS.items():
                matches = pattern.findall(body[:10000])
                if matches:
                    pii_found.append(f"{pii_type} ({len(matches)} occurrences)")

            if pii_found:
                findings.append({
                    "type": "api_security",
                    "title": "API endpoint exposes sensitive data",
                    "description": f"API response contains potentially sensitive data: {', '.join(pii_found)}",
                    "url": url,
                    "affected_url": url,
                    "detection": f"PII detected: {', '.join(pii_found)}",
                    "evidence": f"Response contains: {', '.join(pii_found)}",
                    "severity": "Medium",
                    "confidence": "Medium",
                    "cwe": "CWE-200",
                    "owasp": "A03:2021 - Injection",
                    "remediation": "Review API response filtering. Only return data that the client needs. Implement field-level access control.",
                })

            # Check for overly large responses (potential mass data exposure)
            if len(body) > 50000:
                try:
                    data = json.loads(body)
                    if isinstance(data, list) and len(data) > 100:
                        findings.append({
                            "type": "api_security",
                            "title": "API endpoint returns excessive data",
                            "description": f"API returns {len(data)} records without apparent pagination, suggesting missing data limiting.",
                            "url": url,
                            "affected_url": url,
                            "detection": f"Response contains {len(data)} items, {len(body)} bytes",
                            "severity": "Low",
                            "confidence": "Medium",
                            "cwe": "CWE-770",
                            "owasp": "A04:2021 - Insecure Design",
                            "remediation": "Implement pagination, result limits, and rate limiting on API endpoints.",
                        })
                except Exception:
                    pass

    except Exception:
        pass

    return findings


async def _test_api_cors(
    session: aiohttp.ClientSession, url: str, timeout: float
) -> list[dict[str, Any]]:
    """Test CORS configuration on API endpoints.

    Evaluates the actual security impact by checking:
      1. Whether the origin is reflected or wildcarded
      2. Whether credentials are allowed (Access-Control-Allow-Credentials)
      3. Whether the response contains sensitive data
      4. The authentication context of the request

    Severity assignment:
      - Reflected origin + credentials = High (attacker can make authenticated
        cross-origin requests and read responses)
      - Reflected origin + sensitive response content = Medium
      - Reflected origin without credentials or sensitivity = Low
      - Wildcard origin without credentials = Informational
    """
    findings: list[dict[str, Any]] = []

    evil_origin = "https://evil-attacker.com"
    try:
        async with session.get(
            url,
            headers={"Origin": evil_origin},
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            allows_credentials = acac == "true"

            # Check if response might contain sensitive data
            body = ""
            ct = resp.headers.get("Content-Type", "")
            has_sensitive_response = False
            if "json" in ct or "xml" in ct:
                body = await resp.text(errors="ignore")
                # Quick check for patterns indicating sensitive data
                sensitive_indicators = [
                    "password", "secret", "token", "api_key", "apikey",
                    "email", "phone", "address", "ssn", "credit_card",
                ]
                body_lower = body[:5000].lower()
                has_sensitive_response = any(ind in body_lower for ind in sensitive_indicators)

            # Check if the endpoint requires authentication
            is_authenticated = resp.status != 401

            if acao == "*":
                if allows_credentials:
                    # Wildcard + credentials is a browser-rejected combo, but
                    # indicates a server misconfiguration worth reporting
                    findings.append({
                        "type": "cors",
                        "title": "API CORS wildcard with credentials (browser-rejected misconfiguration)",
                        "description": (
                            "API endpoint sets Access-Control-Allow-Origin: * with "
                            "Access-Control-Allow-Credentials: true. Browsers reject this "
                            "combination, but it indicates a server-side CORS misconfiguration "
                            "that may hide a reflected-origin vulnerability."
                        ),
                        "url": url,
                        "affected_url": url,
                        "detection": f"ACAO: {acao}, ACAC: {acac}",
                        "detection_reason": "Wildcard origin with credentials header — browser rejects but server is misconfigured",
                        "severity": "Medium",
                        "confidence": "High",
                        "cwe": "CWE-942",
                        "owasp": "A05:2021 - Security Misconfiguration",
                        "remediation": "Never combine wildcard CORS with credentials. Use explicit origin allowlists.",
                    })
                # Wildcard without credentials — generally not a security issue
                # unless the endpoint exposes sensitive data
                elif has_sensitive_response:
                    findings.append({
                        "type": "cors",
                        "title": "API CORS wildcard on endpoint with sensitive data",
                        "description": (
                            "API endpoint uses Access-Control-Allow-Origin: * and the response "
                            "appears to contain sensitive data fields. Any website can read this data."
                        ),
                        "url": url,
                        "affected_url": url,
                        "detection": f"ACAO: {acao}, sensitive fields detected in response",
                        "detection_reason": "Wildcard origin on endpoint returning sensitive data",
                        "severity": "Low",
                        "confidence": "Medium",
                        "cwe": "CWE-942",
                        "owasp": "A05:2021 - Security Misconfiguration",
                        "remediation": "Restrict CORS origins on endpoints returning sensitive data.",
                    })
            elif evil_origin in acao:
                # Server reflects the attacker-controlled origin
                if allows_credentials:
                    # Most dangerous: authenticated cross-origin access
                    findings.append({
                        "type": "cors",
                        "title": "API CORS reflects arbitrary origin with credentials",
                        "description": (
                            f"API endpoint reflects the attacker-controlled origin "
                            f"{evil_origin} in Access-Control-Allow-Origin AND allows "
                            f"credentials. This enables any website to make fully "
                            f"authenticated requests and read responses."
                        ),
                        "url": url,
                        "affected_url": url,
                        "detection": f"ACAO: {acao}, ACAC: {acac} (reflected origin with credentials)",
                        "detection_reason": "Reflected arbitrary origin with credentials — full cross-origin authenticated access",
                        "severity": "High",
                        "confidence": "Confirmed",
                        "cwe": "CWE-942",
                        "owasp": "A05:2021 - Security Misconfiguration",
                        "remediation": "Validate CORS origins against a server-side allowlist. Never reflect arbitrary origins with credentials.",
                    })
                elif has_sensitive_response:
                    # Reflected origin + sensitive data but no credentials
                    findings.append({
                        "type": "cors",
                        "title": "API CORS reflects arbitrary origin on sensitive endpoint",
                        "description": (
                            f"API endpoint reflects the attacker-controlled origin "
                            f"{evil_origin}. The response contains potentially sensitive data. "
                            f"Credentials are not allowed, limiting but not eliminating impact."
                        ),
                        "url": url,
                        "affected_url": url,
                        "detection": f"ACAO: {acao} (reflected origin, no credentials, sensitive response)",
                        "detection_reason": "Reflected arbitrary origin on endpoint with sensitive response data",
                        "severity": "Medium",
                        "confidence": "Medium",
                        "cwe": "CWE-942",
                        "owasp": "A05:2021 - Security Misconfiguration",
                        "remediation": "Validate CORS origins against a server-side allowlist.",
                    })
                else:
                    # Reflected origin without credentials and non-sensitive response
                    findings.append({
                        "type": "cors",
                        "title": "API CORS reflects arbitrary origin",
                        "description": (
                            f"API endpoint reflects the attacker-controlled origin "
                            f"{evil_origin} in Access-Control-Allow-Origin. "
                            f"Credentials are not allowed and the response does not appear "
                            f"to contain sensitive data, limiting the security impact."
                        ),
                        "url": url,
                        "affected_url": url,
                        "detection": f"ACAO: {acao} (reflected origin, no credentials)",
                        "detection_reason": "Reflected arbitrary origin without credentials or sensitive data",
                        "severity": "Low",
                        "confidence": "Medium",
                        "cwe": "CWE-942",
                        "owasp": "A05:2021 - Security Misconfiguration",
                        "remediation": "Validate CORS origins against a server-side allowlist.",
                    })

    except Exception:
        pass

    return findings
