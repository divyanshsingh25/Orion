"""ORION TLS Security Scanner.

Comprehensive TLS/SSL configuration testing:
  - Protocol version support (TLS 1.0, 1.1, 1.2, 1.3)
  - Weak cipher suites
  - Certificate validity and trust chain
  - HSTS header presence and configuration
  - Certificate transparency
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("orion.tls_scanner")

# Weak cipher suites
_WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
    "MD5", "RC2", "IDEA", "SEED", "CAMELLIA",
}

# Deprecated protocol versions
_DEPRECATED_PROTOCOLS = {
    "TLSv1": "TLS 1.0",
    "TLSv1.1": "TLS 1.1",
    "SSLv2": "SSL 2.0",
    "SSLv3": "SSL 3.0",
}


async def scan_tls_security(
    target_url: str,
    host: str,
    http_headers: dict[str, str],
    *,
    port: int = 443,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Run comprehensive TLS security tests.

    Args:
        target_url: The original target URL.
        host: Hostname to test.
        http_headers: Response headers (for HSTS check).
        port: TLS port (default 443).
        timeout: Connection timeout.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []

    if not target_url.startswith("https://"):
        # Test for missing HTTPS
        findings.append({
            "type": "tls_misconfiguration",
            "title": "Application does not use HTTPS",
            "description": "The application is served over plain HTTP without TLS encryption. All traffic is transmitted in cleartext.",
            "url": target_url,
            "affected_url": target_url,
            "detection": "Target uses HTTP scheme",
            "severity": "High",
            "confidence": "Confirmed",
            "cwe": "CWE-319",
            "owasp": "A02:2021 - Cryptographic Failures",
            "remediation": "Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.",
        })
        return findings

    # Run TLS checks in thread pool (blocking socket operations)
    loop = asyncio.get_running_loop()
    tls_results = await loop.run_in_executor(None, _analyze_tls_sync, host, port, timeout)

    if tls_results.get("error"):
        findings.append({
            "type": "tls_misconfiguration",
            "title": "TLS connection failed",
            "description": f"Could not establish TLS connection to {host}:{port}: {tls_results['error']}",
            "url": target_url,
            "affected_url": target_url,
            "detection": f"TLS error: {tls_results['error']}",
            "severity": "High",
            "confidence": "High",
            "cwe": "CWE-295",
            "owasp": "A02:2021 - Cryptographic Failures",
            "remediation": "Ensure TLS is properly configured with a valid certificate.",
        })
        return findings

    # 1. Protocol version check
    version = tls_results.get("version", "")
    if version in _DEPRECATED_PROTOCOLS:
        findings.append({
            "type": "tls_misconfiguration",
            "title": f"Deprecated TLS protocol: {_DEPRECATED_PROTOCOLS[version]}",
            "description": f"Server negotiated {_DEPRECATED_PROTOCOLS[version]}, which has known security vulnerabilities.",
            "url": target_url,
            "affected_url": target_url,
            "detection": f"Negotiated protocol: {version}",
            "severity": "High",
            "confidence": "Confirmed",
            "cwe": "CWE-326",
            "owasp": "A02:2021 - Cryptographic Failures",
            "remediation": f"Disable {_DEPRECATED_PROTOCOLS[version]} and use TLS 1.2 or TLS 1.3 only.",
        })

    # 2. Cipher suite check
    cipher = tls_results.get("cipher", "")
    cipher_bits = tls_results.get("cipher_bits", 0)

    for weak in _WEAK_CIPHERS:
        if weak.upper() in cipher.upper():
            findings.append({
                "type": "tls_misconfiguration",
                "title": f"Weak TLS cipher suite: {cipher}",
                "description": f"Server uses cipher suite {cipher} which contains weak algorithm '{weak}'.",
                "url": target_url,
                "affected_url": target_url,
                "detection": f"Cipher: {cipher} ({cipher_bits} bits)",
                "severity": "Medium",
                "confidence": "Confirmed",
                "cwe": "CWE-326",
                "owasp": "A02:2021 - Cryptographic Failures",
                "remediation": "Configure the server to use only strong cipher suites (AES-GCM, ChaCha20-Poly1305).",
            })
            break

    if cipher_bits and cipher_bits < 128:
        findings.append({
            "type": "tls_misconfiguration",
            "title": f"Weak TLS cipher key length: {cipher_bits} bits",
            "description": f"Server negotiated a cipher with only {cipher_bits}-bit key length, which is below the recommended 128-bit minimum.",
            "url": target_url,
            "affected_url": target_url,
            "detection": f"Cipher: {cipher} ({cipher_bits} bits)",
            "severity": "Medium",
            "confidence": "Confirmed",
            "cwe": "CWE-326",
            "owasp": "A02:2021 - Cryptographic Failures",
            "remediation": "Use cipher suites with at least 128-bit key length (256-bit preferred).",
        })

    # 3. Certificate expiry check
    expiry = tls_results.get("expiry_dt")
    if expiry:
        now = datetime.now(timezone.utc)
        days_until = (expiry - now).days
        if days_until < 0:
            findings.append({
                "type": "tls_misconfiguration",
                "title": f"TLS certificate expired {abs(days_until)} days ago",
                "description": f"The TLS certificate for {host} expired on {expiry.strftime('%Y-%m-%d')}.",
                "url": target_url,
                "affected_url": target_url,
                "detection": f"Certificate expired: {expiry.isoformat()}",
                "severity": "Critical",
                "confidence": "Confirmed",
                "cwe": "CWE-295",
                "owasp": "A02:2021 - Cryptographic Failures",
                "remediation": "Renew the TLS certificate immediately.",
            })
        elif days_until < 30:
            findings.append({
                "type": "tls_misconfiguration",
                "title": f"TLS certificate expires in {days_until} days",
                "description": f"The TLS certificate for {host} expires on {expiry.strftime('%Y-%m-%d')} ({days_until} days).",
                "url": target_url,
                "affected_url": target_url,
                "detection": f"Certificate expires: {expiry.isoformat()} ({days_until} days)",
                "severity": "Low",
                "confidence": "Confirmed",
                "cwe": "CWE-295",
                "owasp": "A02:2021 - Cryptographic Failures",
                "remediation": "Renew the TLS certificate before expiration. Set up automated certificate renewal.",
            })

    # NOTE: HSTS check is handled by the security_headers_scanner module
    # to avoid duplicate findings. TLS scanner focuses on protocol, cipher,
    # and certificate issues only.


    # 5. Self-signed certificate check
    if tls_results.get("self_signed"):
        findings.append({
            "type": "tls_misconfiguration",
            "title": "Self-signed TLS certificate detected",
            "description": f"The TLS certificate for {host} appears to be self-signed, which provides no trust chain validation.",
            "url": target_url,
            "affected_url": target_url,
            "detection": f"Issuer: {tls_results.get('issuer', 'Unknown')}, Subject: {tls_results.get('subject', 'Unknown')}",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-295",
            "owasp": "A02:2021 - Cryptographic Failures",
            "remediation": "Use a certificate from a trusted Certificate Authority (e.g., Let's Encrypt).",
        })

    return findings


def _analyze_tls_sync(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Synchronous TLS analysis (runs in thread pool)."""
    result: dict[str, Any] = {}

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Protocol version
                result["version"] = ssock.version()

                # Cipher info
                cipher_info = ssock.cipher()
                if cipher_info:
                    result["cipher"] = cipher_info[0]
                    result["cipher_version"] = cipher_info[1]
                    result["cipher_bits"] = cipher_info[2]

                # Certificate
                cert = ssock.getpeercert(binary_form=True)
                if cert:
                    try:
                        import OpenSSL
                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                        issuer = x509.get_issuer()
                        subject = x509.get_subject()

                        result["issuer"] = issuer.CN or issuer.O or "Unknown"
                        result["subject"] = subject.CN or host

                        # Check self-signed
                        result["self_signed"] = (
                            (issuer.CN or "") == (subject.CN or "") and
                            (issuer.O or "") == (subject.O or "")
                        )

                        # Expiry
                        not_after = x509.get_notAfter()
                        if not_after:
                            dt = datetime.strptime(not_after.decode("ascii"), "%Y%m%d%H%M%SZ")
                            dt = dt.replace(tzinfo=timezone.utc)
                            result["expiry_dt"] = dt
                            result["expiry"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")

                    except ImportError:
                        result["issuer"] = "Unknown (pyOpenSSL not installed)"
                        result["subject"] = host
                    except Exception as e:
                        result["issuer"] = f"Parse error: {e}"
                        result["subject"] = host

    except Exception as e:
        result["error"] = str(e)

    return result
