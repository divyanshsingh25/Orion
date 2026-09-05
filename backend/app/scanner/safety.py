"""ORION Scan Safety Layer.

Provides rate limiting, concurrency control, scope enforcement,
timeout management, and non-destructive payload defaults.

All outbound scan requests MUST flow through this layer.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger("orion.safety")

# Destructive HTTP methods that are blocked in safe mode
_DESTRUCTIVE_METHODS = {"DELETE", "PUT", "PATCH"}

# Known internal/private IP ranges (CIDR-like prefixes)
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.",
)

_PRIVATE_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class ScanSafety:
    """Enforces safety constraints on all scan HTTP requests."""

    def __init__(
        self,
        *,
        allowed_origins: list[str],
        max_rps: float = 10.0,
        max_concurrency: int = 5,
        request_timeout: float = 15.0,
        max_duration_seconds: float = 600.0,
        safe_mode: bool = True,
        allow_private: bool = False,
    ) -> None:
        self.allowed_origins = [o.rstrip("/").lower() for o in allowed_origins]
        self.max_rps = max_rps
        self.max_concurrency = max_concurrency
        self.request_timeout = request_timeout
        self.max_duration_seconds = max_duration_seconds
        self.safe_mode = safe_mode
        self.allow_private = allow_private

        # Rate limiter state
        self._min_interval = 1.0 / max_rps if max_rps > 0 else 0
        self._last_request_time = 0.0
        self._rate_lock = asyncio.Lock()

        # Concurrency semaphore
        self._semaphore = asyncio.Semaphore(max_concurrency)

        # Scan start time for duration enforcement
        self._scan_start: float | None = None

        # Request counter
        self.total_requests = 0

    def start_scan(self) -> None:
        """Mark the beginning of a scan for duration tracking."""
        self._scan_start = time.monotonic()
        self.total_requests = 0

    def is_scan_expired(self) -> bool:
        """Check if the overall scan duration has been exceeded."""
        if self._scan_start is None:
            return False
        return (time.monotonic() - self._scan_start) > self.max_duration_seconds

    def is_in_scope(self, url: str) -> bool:
        """Check if *url* is within the authorized scan scope."""
        try:
            parsed = urlparse(url)
        except Exception:
            return False

        host = parsed.hostname or ""

        # Block private targets unless explicitly allowed
        if not self.allow_private:
            if host in _PRIVATE_HOSTS:
                return False
            if any(host.startswith(p) for p in _PRIVATE_PREFIXES):
                return False

        origin = f"{parsed.scheme}://{parsed.netloc}".lower()
        return any(origin == ao or origin.endswith("." + ao.split("://", 1)[-1]) for ao in self.allowed_origins)

    def is_safe_method(self, method: str) -> bool:
        """Return False if *method* is destructive and safe_mode is on."""
        if not self.safe_mode:
            return True
        return method.upper() not in _DESTRUCTIVE_METHODS

    async def acquire(self) -> None:
        """Wait for both rate limit and concurrency slot."""
        # Check scan duration
        if self.is_scan_expired():
            raise ScanTimeoutError("Scan duration limit exceeded")

        # Rate limit
        async with self._rate_lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_request_time)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_time = time.monotonic()

        # Concurrency
        await self._semaphore.acquire()
        self.total_requests += 1

    def release(self) -> None:
        """Release the concurrency slot."""
        self._semaphore.release()

    async def safe_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse | None:
        """Perform an HTTP request with all safety checks applied.

        Returns None if the request is blocked by scope or safety rules.
        """
        if not self.is_in_scope(url):
            logger.debug("Blocked out-of-scope request: %s", url)
            return None

        if not self.is_safe_method(method):
            logger.debug("Blocked destructive method %s on %s", method, url)
            return None

        # Enforce per-request timeout
        kwargs.setdefault("timeout", aiohttp.ClientTimeout(total=self.request_timeout))

        await self.acquire()
        try:
            return await session.request(method, url, **kwargs)
        except asyncio.TimeoutError:
            logger.warning("Request timed out: %s %s", method, url)
            raise
        except Exception:
            raise
        finally:
            self.release()


class ScanTimeoutError(Exception):
    """Raised when the overall scan duration limit is exceeded."""
