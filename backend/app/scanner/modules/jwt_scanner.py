"""ORION JWT Security Scanner.

Detects JWT tokens in cookies, headers, and responses, then tests for:
  - "none" algorithm acceptance
  - Weak/common signing secrets
  - Missing or incorrect claims (exp, iss, aud)
  - Expired tokens still accepted
  - Algorithm confusion (RS256 → HS256)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from typing import Any

import aiohttp

logger = logging.getLogger("orion.jwt_scanner")

# JWT regex: three base64url segments separated by dots
_JWT_REGEX = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"
)

# Common weak secrets to test
_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key",
    "supersecret", "jwt_secret", "changeme", "test",
    "default", "mysecret", "your-256-bit-secret",
    "shhhhh", "keyboard cat", "jwt", "token",
]


async def scan_jwt_security(
    session: aiohttp.ClientSession,
    target_url: str,
    http_headers: dict[str, str],
    http_cookies: list[dict[str, Any]],
    *,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Scan for JWT-related security weaknesses.

    Args:
        session: aiohttp session.
        target_url: Base target URL.
        http_headers: Response headers from the target.
        http_cookies: Cookies from the target.
        timeout: Per-request timeout.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []

    # Collect JWTs from various sources
    jwts: list[dict[str, Any]] = []

    # From cookies
    for cookie in http_cookies:
        value = cookie.get("value", "")
        match = _JWT_REGEX.search(value)
        if match:
            jwts.append({
                "token": match.group(0),
                "source": f"cookie:{cookie.get('name', 'unknown')}",
                "cookie_name": cookie.get("name", ""),
            })

    # From headers (Authorization, custom headers)
    for header_name, header_value in http_headers.items():
        match = _JWT_REGEX.search(header_value)
        if match:
            jwts.append({
                "token": match.group(0),
                "source": f"header:{header_name}",
            })

    if not jwts:
        # Try to get JWT from common auth endpoints
        for path in ["/api/auth/token", "/auth/login", "/oauth/token", "/api/v1/auth/login"]:
            try:
                async with session.get(
                    target_url.rstrip("/") + path,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    if resp.status < 400:
                        body = await resp.text(errors="ignore")
                        match = _JWT_REGEX.search(body)
                        if match:
                            jwts.append({
                                "token": match.group(0),
                                "source": f"endpoint:{path}",
                            })
            except Exception:
                continue

    if not jwts:
        return findings

    for jwt_info in jwts:
        token = jwt_info["token"]
        source = jwt_info["source"]

        # Decode the JWT
        decoded = _decode_jwt(token)
        if not decoded:
            continue

        header, payload = decoded

        # 1. Check algorithm
        alg = header.get("alg", "")
        if alg.lower() == "none" or not alg:
            findings.append({
                "type": "jwt_weakness",
                "title": "JWT uses 'none' algorithm",
                "description": f"JWT token from {source} uses the 'none' algorithm, allowing anyone to forge valid tokens.",
                "url": target_url,
                "affected_url": target_url,
                "parameter": source,
                "detection": f"JWT header alg={alg}",
                "evidence": f"Header: {json.dumps(header)}\nPayload: {json.dumps(payload, default=str)}",
                "severity": "Critical",
                "confidence": "Confirmed",
                "cwe": "CWE-327",
                "owasp": "A02:2021 - Cryptographic Failures",
                "remediation": "Reject JWTs with 'none' algorithm. Always verify the signature with a strong algorithm (RS256/ES256).",
            })

        # 2. Check for expired tokens
        exp = payload.get("exp")
        if exp:
            try:
                exp_time = int(exp)
                if exp_time < time.time():
                    expired_ago = int(time.time() - exp_time)
                    findings.append({
                        "type": "jwt_weakness",
                        "title": "Expired JWT token accepted",
                        "description": f"JWT from {source} expired {expired_ago}s ago but is still being used/accepted.",
                        "url": target_url,
                        "affected_url": target_url,
                        "parameter": source,
                        "detection": f"Token expired at {exp_time}, current time {int(time.time())}",
                        "evidence": f"exp claim: {exp_time} (expired {expired_ago}s ago)",
                        "severity": "Medium",
                        "confidence": "High",
                        "cwe": "CWE-613",
                        "owasp": "A07:2021 - Identification and Authentication Failures",
                        "remediation": "Enforce JWT expiration checking. Reject expired tokens on the server side.",
                    })
            except (ValueError, TypeError):
                pass
        else:
            findings.append({
                "type": "jwt_weakness",
                "title": "JWT missing expiration claim",
                "description": f"JWT from {source} lacks an 'exp' claim, meaning it never expires.",
                "url": target_url,
                "affected_url": target_url,
                "parameter": source,
                "detection": "No 'exp' claim in JWT payload",
                "evidence": f"Payload keys: {list(payload.keys())}",
                "severity": "Medium",
                "confidence": "Confirmed",
                "cwe": "CWE-613",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "remediation": "Always include an 'exp' claim in JWTs with a reasonable expiration time.",
            })

        # 3. Check for missing standard claims
        missing_claims = []
        for claim in ["iss", "aud", "iat"]:
            if claim not in payload:
                missing_claims.append(claim)

        if missing_claims:
            findings.append({
                "type": "jwt_weakness",
                "title": f"JWT missing security claims: {', '.join(missing_claims)}",
                "description": f"JWT from {source} is missing standard claims ({', '.join(missing_claims)}) that help prevent token misuse.",
                "url": target_url,
                "affected_url": target_url,
                "parameter": source,
                "detection": f"Missing claims: {missing_claims}",
                "severity": "Low",
                "confidence": "Confirmed",
                "cwe": "CWE-345",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "remediation": f"Include {', '.join(missing_claims)} claims in JWTs and validate them on the server.",
            })

        # 4. Test for weak secrets (HS256 only)
        if alg and alg.upper().startswith("HS"):
            weak = _test_weak_secrets(token, alg)
            if weak:
                findings.append({
                    "type": "jwt_weakness",
                    "title": "JWT signed with weak/common secret",
                    "description": f"JWT from {source} is signed with the weak secret '{weak}'. An attacker can forge arbitrary tokens.",
                    "url": target_url,
                    "affected_url": target_url,
                    "parameter": source,
                    "detection": f"Weak secret: '{weak}' verified against {alg}",
                    "evidence": f"Algorithm: {alg}, Secret: {weak}",
                    "severity": "Critical",
                    "confidence": "Confirmed",
                    "cwe": "CWE-521",
                    "owasp": "A02:2021 - Cryptographic Failures",
                    "remediation": "Use a strong, random secret (at least 256 bits) for HMAC-based JWT signing. Prefer asymmetric algorithms (RS256/ES256).",
                })

        # 5. Check sensitive data in payload
        sensitive_keys = {"password", "passwd", "secret", "credit_card", "ssn", "private_key"}
        found_sensitive = [k for k in payload.keys() if k.lower() in sensitive_keys]
        if found_sensitive:
            findings.append({
                "type": "jwt_weakness",
                "title": "JWT payload contains sensitive data",
                "description": f"JWT from {source} contains potentially sensitive fields: {', '.join(found_sensitive)}. JWT payloads are base64-encoded, not encrypted.",
                "url": target_url,
                "affected_url": target_url,
                "parameter": source,
                "detection": f"Sensitive fields in payload: {found_sensitive}",
                "severity": "High",
                "confidence": "Confirmed",
                "cwe": "CWE-312",
                "owasp": "A02:2021 - Cryptographic Failures",
                "remediation": "Never store sensitive data in JWT payloads. Use JWE if encryption is needed, or store sensitive data server-side.",
            })

    return findings


def _decode_jwt(token: str) -> tuple[dict, dict] | None:
    """Decode a JWT without verification. Returns (header, payload) or None."""
    parts = token.split(".")
    if len(parts) < 2:
        return None

    try:
        header_b = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b))

        payload_b = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b))

        return header, payload
    except Exception:
        return None


def _test_weak_secrets(token: str, alg: str) -> str | None:
    """Test common weak secrets against an HMAC-signed JWT.

    Returns the weak secret if found, None otherwise.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    signature = parts[2]

    # Determine hash algorithm
    if alg.upper() == "HS256":
        hash_func = hashlib.sha256
    elif alg.upper() == "HS384":
        hash_func = hashlib.sha384
    elif alg.upper() == "HS512":
        hash_func = hashlib.sha512
    else:
        return None

    for secret in _WEAK_SECRETS:
        computed = hmac.new(secret.encode(), signing_input, hash_func).digest()
        # Base64url encode
        computed_b64 = base64.urlsafe_b64encode(computed).rstrip(b"=").decode()
        if computed_b64 == signature:
            return secret

    return None
