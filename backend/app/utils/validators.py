from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

import validators

from app.core.config import get_settings


settings = get_settings()


@dataclass(frozen=True)
class ParsedTarget:
    url: str
    scheme: str
    host: str
    port: int | None


class TargetValidationError(ValueError):
    pass


def parse_and_validate_target(url: str) -> ParsedTarget:
    if not validators.url(url):
        raise TargetValidationError("Target must be a valid URL")

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise TargetValidationError("Only HTTP and HTTPS targets are supported")
    if not parsed.hostname:
        raise TargetValidationError("Target host is required")

    host = parsed.hostname
    if not settings.allow_private_targets:
        _assert_public_host(host)

    return ParsedTarget(url=url, scheme=parsed.scheme, host=host, port=parsed.port)


def _assert_public_host(host: str) -> None:
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise TargetValidationError("Unable to resolve target host") from exc

    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise TargetValidationError("Private or local targets are disabled by policy")
