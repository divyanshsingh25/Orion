"""ORION Authentication Handler.

Supports multiple authentication schemes for scanning authenticated
attack surfaces:
  - form: POST credentials to a login URL, capture session cookies
  - cookie: Inject user-provided cookies directly
  - bearer: Inject a Bearer token header
  - api_key: Inject an API key header

Returns an authenticated aiohttp.ClientSession ready for scanning.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin

import aiohttp

logger = logging.getLogger("orion.auth")


class AuthHandler:
    """Prepares an authenticated HTTP session for scanning."""

    def __init__(self, auth_config: dict[str, Any] | None = None) -> None:
        self._config = auth_config or {}
        self.auth_type = self._config.get("auth_type", "").lower()
        self._extra_headers: dict[str, str] = {}
        self._extra_cookies: dict[str, str] = {}
        self._authenticated = False

    @property
    def is_configured(self) -> bool:
        return bool(self.auth_type)

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    async def authenticate(self, session: aiohttp.ClientSession, target_url: str) -> bool:
        """Perform authentication based on the configured type.

        Modifies *session* in-place (cookies) and populates extra headers.
        Returns True on success.
        """
        if not self.is_configured:
            return True  # Nothing to do

        try:
            if self.auth_type == "form":
                return await self._form_login(session, target_url)
            elif self.auth_type == "cookie":
                return self._cookie_inject()
            elif self.auth_type == "bearer":
                return self._bearer_inject()
            elif self.auth_type == "api_key":
                return self._api_key_inject()
            else:
                logger.warning("Unknown auth type: %s", self.auth_type)
                return False
        except Exception as exc:
            logger.error("Authentication failed: %s", exc)
            return False

    async def _form_login(self, session: aiohttp.ClientSession, target_url: str) -> bool:
        """POST credentials to a login URL and capture session cookies."""
        login_url = self._config.get("login_url", "")
        if not login_url:
            login_url = urljoin(target_url, "/login")

        username_field = self._config.get("username_field", "username")
        password_field = self._config.get("password_field", "password")
        username = self._config.get("username", "")
        password = self._config.get("password", "")

        if not username or not password:
            logger.warning("Form auth configured but credentials are empty")
            return False

        form_data = {
            username_field: username,
            password_field: password,
        }

        # Add any extra fields the user specified
        extra_fields = self._config.get("extra_fields", {})
        if isinstance(extra_fields, dict):
            form_data.update(extra_fields)

        try:
            async with session.post(
                login_url,
                data=form_data,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status < 400:
                    # Session cookies are automatically captured by aiohttp
                    cookie_count = len(session.cookie_jar)
                    logger.info(
                        "Form login successful: %s (status %d, %d cookies)",
                        login_url, resp.status, cookie_count,
                    )
                    self._authenticated = True
                    return True
                else:
                    logger.warning("Form login returned status %d", resp.status)
                    # Still proceed — some apps return 403 but set a session
                    self._authenticated = True
                    return True
        except Exception as exc:
            logger.error("Form login failed for %s: %s", login_url, exc)
            return False

    def _cookie_inject(self) -> bool:
        """Prepare cookies for injection into the session."""
        cookies = self._config.get("cookies", "")
        if isinstance(cookies, str):
            # Parse "name=value; name2=value2" format
            for pair in cookies.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    name, value = pair.split("=", 1)
                    self._extra_cookies[name.strip()] = value.strip()
        elif isinstance(cookies, dict):
            self._extra_cookies.update(cookies)

        if self._extra_cookies:
            logger.info("Cookie auth: %d cookies configured", len(self._extra_cookies))
            self._authenticated = True
            return True

        logger.warning("Cookie auth configured but no cookies provided")
        return False

    def _bearer_inject(self) -> bool:
        """Prepare Bearer token header."""
        token = self._config.get("token", "")
        if token:
            self._extra_headers["Authorization"] = f"Bearer {token}"
            logger.info("Bearer auth configured")
            self._authenticated = True
            return True

        logger.warning("Bearer auth configured but no token provided")
        return False

    def _api_key_inject(self) -> bool:
        """Prepare API key header."""
        header_name = self._config.get("header_name", "X-API-Key")
        api_key = self._config.get("api_key", "")
        if api_key:
            self._extra_headers[header_name] = api_key
            logger.info("API key auth configured (header: %s)", header_name)
            self._authenticated = True
            return True

        logger.warning("API key auth configured but no key provided")
        return False

    def get_extra_headers(self) -> dict[str, str]:
        """Return any extra headers to include in all scan requests."""
        return dict(self._extra_headers)

    def get_extra_cookies(self) -> dict[str, str]:
        """Return any extra cookies to include in all scan requests."""
        return dict(self._extra_cookies)

    def apply_to_session(self, session: aiohttp.ClientSession) -> None:
        """Apply extra cookies/headers to an existing session."""
        for name, value in self._extra_cookies.items():
            session.cookie_jar.update_cookies({name: value})
