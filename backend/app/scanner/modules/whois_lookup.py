"""Real WHOIS lookup module.

Collects domain, registrar, creation/expiry/update dates, name servers,
domain status, and registrant info when publicly available.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import whois


def _to_str(value: Any) -> str | None:
    """Convert WHOIS field value to a JSON-friendly string."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


async def run_whois_lookup(host: str) -> dict[str, Any]:
    """Perform a real WHOIS lookup for *host*.

    Returns a structured dict.  If WHOIS is unavailable the dict contains
    ``{"status": "WHOIS information unavailable"}``.
    """

    if not host:
        return {"status": "WHOIS information unavailable"}

    try:
        record = await asyncio.to_thread(whois.whois, host)
    except Exception:
        return {"status": "WHOIS information unavailable"}

    if record is None or (hasattr(record, "text") and not record.text):
        return {"status": "WHOIS information unavailable"}

    result: dict[str, Any] = {"status": "ok"}

    field_map = {
        "domain_name": "domain",
        "registrar": "registrar",
        "creation_date": "creation_date",
        "expiration_date": "expiration_date",
        "updated_date": "updated_date",
        "name_servers": "name_servers",
        "status": "domain_status",
        "org": "registrant_organization",
        "country": "registrant_country",
        "state": "registrant_state",
        "emails": "contact_emails",
    }

    for whois_key, output_key in field_map.items():
        raw = getattr(record, whois_key, None) if hasattr(record, whois_key) else record.get(whois_key)
        converted = _to_str(raw)
        if converted:
            result[output_key] = converted

    # Store raw WHOIS text if available
    if hasattr(record, "text") and record.text:
        result["raw"] = record.text[:4000]  # cap length

    if len(result) <= 1:
        result["status"] = "WHOIS information unavailable"

    return result
