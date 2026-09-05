"""ORION Evidence Collector.

Wraps aiohttp requests to automatically capture full HTTP request/response
pairs as evidence for vulnerability findings.  Also provides a verification
replay to confirm findings before marking them as "confirmed".
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp

logger = logging.getLogger("orion.evidence")

# Max bytes of response body to capture (keep evidence manageable)
_MAX_BODY_CAPTURE = 4096


@dataclass
class CapturedExchange:
    """A single captured HTTP request/response pair."""

    method: str = "GET"
    url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    status_code: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    elapsed_ms: float = 0.0
    error: str | None = None

    def as_request_str(self) -> str:
        """Format the request as a human-readable string."""
        lines = [f"{self.method} {self.url}"]
        for k, v in self.request_headers.items():
            if k.lower() not in ("cookie", "authorization"):
                lines.append(f"{k}: {v}")
            else:
                lines.append(f"{k}: [REDACTED]")
        if self.request_body:
            lines.append("")
            lines.append(self.request_body[:1024])
        return "\n".join(lines)

    def as_response_str(self) -> str:
        """Format the response as a human-readable string."""
        lines = [f"HTTP {self.status_code}"]
        for k, v in self.response_headers.items():
            lines.append(f"{k}: {v}")
        if self.response_body:
            lines.append("")
            lines.append(self.response_body[:2048])
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "request_headers": {k: v for k, v in self.request_headers.items()
                                if k.lower() not in ("cookie", "authorization")},
            "request_body": (self.request_body or "")[:1024],
            "status_code": self.status_code,
            "response_headers": dict(self.response_headers),
            "response_body": self.response_body[:2048],
            "elapsed_ms": round(self.elapsed_ms, 1),
            "error": self.error,
        }


class EvidenceCollector:
    """Wraps an aiohttp.ClientSession to capture request/response evidence."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        self._session = session
        self._captures: list[CapturedExchange] = []

    @property
    def session(self) -> aiohttp.ClientSession:
        return self._session

    @property
    def captures(self) -> list[CapturedExchange]:
        return list(self._captures)

    async def request(
        self,
        method: str,
        url: str,
        *,
        capture: bool = True,
        **kwargs: Any,
    ) -> tuple[aiohttp.ClientResponse | None, CapturedExchange]:
        """Perform an HTTP request and capture the exchange.

        Returns ``(response, captured_exchange)``.  If the request fails,
        response is ``None`` and the exchange contains the error.
        """
        exchange = CapturedExchange(method=method.upper(), url=url)

        # Capture request details
        headers = kwargs.get("headers", {})
        exchange.request_headers = dict(headers) if headers else {}
        data = kwargs.get("data")
        json_body = kwargs.get("json")
        if json_body is not None:
            exchange.request_body = json.dumps(json_body, ensure_ascii=False)[:1024]
        elif data is not None:
            exchange.request_body = str(data)[:1024]

        t0 = time.monotonic()
        try:
            resp = await self._session.request(method, url, **kwargs)
            exchange.elapsed_ms = (time.monotonic() - t0) * 1000
            exchange.status_code = resp.status
            exchange.response_headers = {k: v for k, v in resp.headers.items()}

            # Read response body (only if text-like)
            ct = resp.headers.get("Content-Type", "")
            if any(t in ct for t in ("text/", "json", "xml", "html", "javascript")):
                body = await resp.text(errors="ignore")
                exchange.response_body = body[:_MAX_BODY_CAPTURE]

            if capture:
                self._captures.append(exchange)
            return resp, exchange

        except Exception as exc:
            exchange.elapsed_ms = (time.monotonic() - t0) * 1000
            exchange.error = str(exc)
            if capture:
                self._captures.append(exchange)
            return None, exchange

    async def get(self, url: str, **kwargs: Any) -> tuple[aiohttp.ClientResponse | None, CapturedExchange]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> tuple[aiohttp.ClientResponse | None, CapturedExchange]:
        return await self.request("POST", url, **kwargs)

    async def verify_finding(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:
        """Attempt to replay and verify a finding.

        Sends the original payload again and checks whether the response
        still exhibits the vulnerability indicator.  Updates the finding's
        confidence based on the result.
        """
        url = finding.get("affected_url") or finding.get("url", "")
        method = finding.get("method", "GET").upper()
        payload = finding.get("payload")

        if not url:
            return finding

        kwargs: dict[str, Any] = {}
        if payload and method == "POST":
            kwargs["data"] = payload
        elif payload and method == "GET":
            # Payload is typically injected via URL for GET
            pass

        try:
            resp, exchange = await self.request(method, url, **kwargs)
            if resp is None:
                finding["verification_status"] = "unreachable"
                finding["confidence"] = finding.get("confidence", "Medium")
                return finding

            # Check if the vulnerability indicator is present in the response
            indicator = finding.get("detection") or finding.get("detection_technique") or ""
            body = exchange.response_body.lower()

            verified = False
            if indicator and indicator.lower() in body:
                verified = True
            elif payload and str(payload).lower() in body:
                # Reflected payload — strong indicator for XSS, injection
                verified = True
            elif exchange.status_code == finding.get("original_status", 0):
                # Same status code as original detection
                verified = True

            if verified:
                finding["confidence"] = "Confirmed"
                finding["verification_status"] = "confirmed"
                finding["verification_evidence"] = exchange.as_response_str()[:1024]
            else:
                finding["verification_status"] = "not_reproduced"
                # Don't downgrade if already High confidence
                if finding.get("confidence", "").lower() not in ("high", "confirmed"):
                    finding["confidence"] = "Low"

        except Exception as exc:
            finding["verification_status"] = f"error: {exc}"

        return finding

    def build_evidence_text(self, exchange: CapturedExchange) -> str:
        """Format a captured exchange into evidence text for a finding."""
        parts = []
        parts.append("=== HTTP Request ===")
        parts.append(exchange.as_request_str())
        parts.append("")
        parts.append("=== HTTP Response ===")
        parts.append(exchange.as_response_str())
        if exchange.error:
            parts.append(f"\n=== Error ===\n{exchange.error}")
        return "\n".join(parts)

    def get_recent_captures(self, n: int = 5) -> list[CapturedExchange]:
        """Return the most recent *n* captured exchanges."""
        return self._captures[-n:]

    def clear(self) -> None:
        """Clear all captured exchanges."""
        self._captures.clear()
