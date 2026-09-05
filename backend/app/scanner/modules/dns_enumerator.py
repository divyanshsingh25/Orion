"""Real DNS enumeration module.

Resolves A, AAAA, CNAME, MX, NS, TXT, SOA records using dnspython.
Also performs safe subdomain discovery via common-prefix brute-force.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Awaitable

import dns.resolver
import dns.exception


RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
    "portal", "vpn", "remote", "webmail", "smtp", "pop", "imap",
    "ns1", "ns2", "dns", "cdn", "static", "assets", "img", "images",
    "media", "blog", "shop", "store", "app", "m", "mobile", "beta",
    "demo", "docs", "wiki", "support", "help", "status", "monitor",
    "git", "gitlab", "jenkins", "ci", "dashboard", "auth", "sso",
    "login", "secure", "gateway", "proxy",
]


EmitFn = Callable[[dict[str, Any]], Awaitable[None] | None]


async def run_dns_enumeration(
    host: str,
    *,
    emit: EmitFn | None = None,
) -> dict[str, Any]:
    """Enumerate DNS records for *host* and return structured results.

    Returns a dict like::

        {
            "host": "example.com",
            "records": {"A": [...], "MX": [...], ...},
            "subdomains": [{"subdomain": "www.example.com", "ips": [...]}],
            "status": "ok" | "error",
        }
    """

    result: dict[str, Any] = {
        "host": host,
        "records": {},
        "subdomains": [],
        "status": "ok",
    }

    if not host:
        result["status"] = "error"
        return result

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    # --- resolve standard record types ---
    for rtype in RECORD_TYPES:
        try:
            answers = await asyncio.to_thread(resolver.resolve, host, rtype)
            values: list[dict[str, Any]] = []
            for rdata in answers:
                entry: dict[str, Any] = {"value": str(rdata)}
                if hasattr(answers, "rrset") and answers.rrset is not None:
                    entry["ttl"] = int(answers.rrset.ttl)
                values.append(entry)
            if values:
                result["records"][rtype] = values
                if emit:
                    for v in values:
                        await _safe_emit(emit, f"[DNS] {rtype} record: {v['value']}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, Exception):
            continue

    if emit:
        total = sum(len(v) for v in result["records"].values())
        await _safe_emit(emit, f"[DNS] Enumeration complete — {total} records found")

    # --- safe subdomain discovery ---
    if emit:
        await _safe_emit(emit, "[DNS] Starting subdomain discovery")

    discovered: list[dict[str, Any]] = []
    tasks = [_resolve_subdomain(resolver, f"{sub}.{host}") for sub in COMMON_SUBDOMAINS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for sub_name, sub_result in zip(COMMON_SUBDOMAINS, results):
        if isinstance(sub_result, Exception) or not sub_result:
            continue
        fqdn = f"{sub_name}.{host}"
        discovered.append({"subdomain": fqdn, "ips": sub_result})
        if emit:
            await _safe_emit(emit, f"[DNS] Subdomain found: {fqdn} -> {', '.join(sub_result)}")

    result["subdomains"] = discovered

    if emit:
        await _safe_emit(emit, f"[DNS] Subdomain discovery complete - {len(discovered)} found")

    return result


async def _resolve_subdomain(resolver: dns.resolver.Resolver, fqdn: str) -> list[str]:
    """Try to resolve a subdomain, return list of IPs or empty list."""
    try:
        answers = await asyncio.to_thread(resolver.resolve, fqdn, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


async def _safe_emit(emit: EmitFn, message: str) -> None:
    import asyncio as _aio

    result = emit({"log_message": message})
    if _aio.iscoroutine(result):
        await result
