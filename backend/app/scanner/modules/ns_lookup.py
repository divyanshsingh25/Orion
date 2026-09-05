"""DNS / NS lookup module.

Resolves hostname → IP, name servers, and DNS records.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import dns.resolver
import dns.reversename


async def run_ns_lookup(host: str) -> dict[str, Any]:
    """Return hostname, IPs, name servers, and resolution status."""

    result: dict[str, Any] = {
        "hostname": host,
        "ips": [],
        "name_servers": [],
        "dns_records": {},
        "resolution_status": "unknown",
    }

    if not host:
        result["resolution_status"] = "error"
        return result

    # --- resolve IPs ---
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
        ips = sorted({info[4][0] for info in infos})
        result["ips"] = ips
        result["resolution_status"] = "resolved"
    except socket.gaierror:
        result["resolution_status"] = "failed"
        return result

    # --- resolve NS records ---
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    try:
        ns_answers = await asyncio.to_thread(resolver.resolve, host, "NS")
        result["name_servers"] = [str(ns) for ns in ns_answers]
    except Exception:
        pass

    # Collect a few useful record types
    for rtype in ("A", "AAAA", "CNAME", "MX", "TXT"):
        try:
            answers = await asyncio.to_thread(resolver.resolve, host, rtype)
            result["dns_records"][rtype] = [str(r) for r in answers]
        except Exception:
            continue

    return result
