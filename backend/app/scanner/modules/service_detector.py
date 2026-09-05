"""Service detection module.

Detects service name and version from banners and HTTP headers.
"""

from __future__ import annotations

import re
from typing import Any


# Patterns: compiled regex → (service_name_template, version_group_index)
_BANNER_PATTERNS: list[tuple[re.Pattern[str], str, int | None]] = [
    (re.compile(r"OpenSSH[_/ ]?([\d.p]+)", re.I), "OpenSSH", 1),
    (re.compile(r"Apache[/ ]?([\d.]+)?", re.I), "Apache", 1),
    (re.compile(r"nginx[/ ]?([\d.]+)?", re.I), "Nginx", 1),
    (re.compile(r"Microsoft-IIS[/ ]?([\d.]+)?", re.I), "Microsoft IIS", 1),
    (re.compile(r"MySQL[/ ]?([\d.]+)?", re.I), "MySQL", 1),
    (re.compile(r"MariaDB[/ ]?([\d.]+)?", re.I), "MariaDB", 1),
    (re.compile(r"PostgreSQL[/ ]?([\d.]+)?", re.I), "PostgreSQL", 1),
    (re.compile(r"Redis[: ]?v?([\d.]+)?", re.I), "Redis", 1),
    (re.compile(r"MongoDB", re.I), "MongoDB", None),
    (re.compile(r"vsftpd ([\d.]+)", re.I), "vsftpd", 1),
    (re.compile(r"ProFTPD ([\d.]+)", re.I), "ProFTPD", 1),
    (re.compile(r"Pure-FTPd", re.I), "Pure-FTPd", None),
    (re.compile(r"FileZilla Server ([\d.]+)", re.I), "FileZilla Server", 1),
    (re.compile(r"Postfix", re.I), "Postfix", None),
    (re.compile(r"Exim ([\d.]+)", re.I), "Exim", 1),
    (re.compile(r"Dovecot", re.I), "Dovecot", None),
    (re.compile(r"LiteSpeed", re.I), "LiteSpeed", None),
    (re.compile(r"Caddy", re.I), "Caddy", None),
    (re.compile(r"Express", re.I), "Express.js", None),
    (re.compile(r"Kestrel", re.I), "Kestrel", None),
    (re.compile(r"Gunicorn[/ ]?([\d.]+)?", re.I), "Gunicorn", 1),
    (re.compile(r"Werkzeug[/ ]?([\d.]+)?", re.I), "Werkzeug", 1),
    (re.compile(r"uvicorn", re.I), "Uvicorn", None),
    (re.compile(r"Jetty[/ ]?([\d.]+)?", re.I), "Jetty", 1),
    (re.compile(r"Tomcat[/ ]?([\d.]+)?", re.I), "Apache Tomcat", 1),
    (re.compile(r"WildFly[/ ]?([\d.]+)?", re.I), "WildFly", 1),
]


def detect_services(
    open_ports: list[dict[str, Any]],
    http_headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Detect service name + version for each open port.

    Parameters
    ----------
    open_ports
        Output from ``port_scanner.run_port_scan``.
    http_headers
        Headers from the primary HTTP response, if available.

    Returns
    -------
    list[dict]
        Each element contains ``service``, ``version``, ``port``,
        ``confidence``, ``evidence``.
    """

    results: list[dict[str, Any]] = []

    for entry in open_ports:
        banner = entry.get("banner", "")
        port = entry["port"]
        base_service = entry.get("service", "unknown")

        service, version, confidence, evidence = _match_banner(banner)

        if not service:
            service = base_service
            confidence = "Low"
            evidence = f"Port {port} default service mapping"

        results.append({
            "service": service,
            "version": version,
            "port": port,
            "protocol": entry.get("protocol", "tcp"),
            "confidence": confidence,
            "evidence": evidence,
        })

    # Augment from HTTP headers if available
    if http_headers:
        server = http_headers.get("Server", "")
        powered_by = http_headers.get("X-Powered-By", "")

        if server:
            svc, ver, _, _ = _match_banner(server)
            if svc:
                _upsert_service(results, svc, ver, 443 if "https" in server.lower() else 80,
                                "High", f"Server header: {server}")
        if powered_by:
            svc, ver, _, _ = _match_banner(powered_by)
            if svc:
                _upsert_service(results, svc, ver, 80, "Medium",
                                f"X-Powered-By header: {powered_by}")

    return results


def _match_banner(banner: str) -> tuple[str | None, str | None, str, str]:
    """Match a banner against known patterns.

    Returns (service, version, confidence, evidence).
    """
    if not banner:
        return None, None, "Low", ""

    for pattern, service_name, version_group in _BANNER_PATTERNS:
        m = pattern.search(banner)
        if m:
            version = m.group(version_group).strip() if version_group and m.lastindex and m.lastindex >= version_group else None
            conf = "High" if version else "Medium"
            return service_name, version, conf, banner[:256]

    return None, None, "Low", banner[:256]


def _upsert_service(
    services: list[dict[str, Any]],
    service: str,
    version: str | None,
    port: int,
    confidence: str,
    evidence: str,
) -> None:
    """Add or update a service entry."""
    for svc in services:
        if svc["port"] == port:
            if confidence in ("High", "Medium") and svc["confidence"] == "Low":
                svc["service"] = service
                svc["version"] = version
                svc["confidence"] = confidence
                svc["evidence"] = evidence
            return
    services.append({
        "service": service,
        "version": version,
        "port": port,
        "protocol": "tcp",
        "confidence": confidence,
        "evidence": evidence,
    })
