"""Safe TCP port scanner.

Uses asyncio.open_connection for non-destructive TCP connect scanning.
Grabs banners when possible.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Awaitable


# Top ~100 common ports
COMMON_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135,
    139, 143, 161, 162, 389, 443, 445, 465, 514,
    515, 587, 631, 636, 993, 995, 1080, 1433, 1521,
    1723, 2049, 2082, 2083, 2086, 2087, 3000, 3306,
    3389, 5432, 5500, 5601, 5672, 5900, 5984, 6379,
    6443, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
    9090, 9200, 9300, 9418, 9999, 10000, 11211, 27017,
    27018, 28017, 50000,
]

# Well-known port → service name mapping
PORT_SERVICE_MAP: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 119: "NNTP",
    135: "MSRPC", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 515: "LPD", 587: "Submission",
    631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2086: "WHM", 2087: "WHM-SSL", 3000: "Dev-Server",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5500: "VNC", 5601: "Kibana", 5672: "AMQP", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "K8s-API",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8080: "HTTP-Proxy",
    8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "HTTP-Alt", 9090: "HTTP-Alt", 9200: "Elasticsearch",
    9300: "ES-Transport", 9418: "Git", 9999: "HTTP-Alt",
    10000: "Webmin", 11211: "Memcached", 27017: "MongoDB",
    27018: "MongoDB", 28017: "MongoDB-Web", 50000: "SAP",
}


EmitFn = Callable[[dict[str, Any]], Awaitable[None] | None]


async def run_port_scan(
    host: str,
    *,
    ports: list[int] | None = None,
    timeout: float = 3.0,
    concurrency: int = 50,
    emit: EmitFn | None = None,
) -> list[dict[str, Any]]:
    """Scan *host* for open TCP ports.

    Returns a list of dicts, each describing one open port::

        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "service": "HTTPS",
            "banner": "...",
            "response_time_ms": 12.3,
        }
    """

    scan_ports = ports or COMMON_PORTS

    if emit:
        await _safe_emit(emit, f"[PORT] Scanning {len(scan_ports)} ports on {host}")

    semaphore = asyncio.Semaphore(concurrency)
    results: list[dict[str, Any]] = []

    async def _probe(port: int) -> dict[str, Any] | None:
        async with semaphore:
            return await _tcp_connect(host, port, timeout)

    tasks = [_probe(p) for p in scan_ports]
    raw = await asyncio.gather(*tasks, return_exceptions=True)

    for port, outcome in zip(scan_ports, raw):
        if isinstance(outcome, Exception) or outcome is None:
            continue
        results.append(outcome)
        if emit:
            svc = outcome.get("service", "unknown")
            await _safe_emit(emit, f"[PORT] {port}/tcp OPEN — {svc}")

    results.sort(key=lambda r: r["port"])

    if emit:
        await _safe_emit(emit, f"[PORT] Scan complete — {len(results)} open ports")

    return results


async def _tcp_connect(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Attempt a TCP connection and optional banner grab."""
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return None

    elapsed_ms = round((time.monotonic() - start) * 1000, 1)
    service = PORT_SERVICE_MAP.get(port, "unknown")
    banner = ""

    # Try banner grab
    try:
        # Send a small probe for HTTP-like services
        if port in (80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 9000, 9090, 3000):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            await writer.drain()

        data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        banner = data.decode("utf-8", errors="replace").strip()[:512]

        # Try to extract service from banner
        if banner:
            detected = _detect_service_from_banner(banner)
            if detected:
                service = detected

    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return {
        "port": port,
        "protocol": "tcp",
        "state": "open",
        "service": service,
        "banner": banner,
        "response_time_ms": elapsed_ms,
    }


def _detect_service_from_banner(banner: str) -> str | None:
    """Extract a service name from a banner string."""
    bl = banner.lower()
    if "openssh" in bl:
        return "OpenSSH"
    if "ssh" in bl:
        return "SSH"
    if "apache" in bl:
        return "Apache"
    if "nginx" in bl:
        return "Nginx"
    if "microsoft-iis" in bl or "iis" in bl:
        return "Microsoft IIS"
    if "http" in bl and ("200" in bl or "301" in bl or "302" in bl or "404" in bl):
        return "HTTP"
    if "mysql" in bl or "mariadb" in bl:
        return "MySQL"
    if "postgresql" in bl or "postgres" in bl:
        return "PostgreSQL"
    if "redis" in bl:
        return "Redis"
    if "mongodb" in bl:
        return "MongoDB"
    if "ftp" in bl or "vsftpd" in bl or "proftpd" in bl:
        return "FTP"
    if "smtp" in bl or "postfix" in bl or "exim" in bl:
        return "SMTP"
    return None


async def _safe_emit(emit: EmitFn, message: str) -> None:
    import asyncio as _aio
    result = emit({"log_message": message})
    if _aio.iscoroutine(result):
        await result
