from __future__ import annotations

import re
from typing import Any

# Sensitive patterns to redact
_SENSITIVE_PATTERNS = [
    # Authorization & Bearer tokens
    (r"(?i)(authorization\s*:\s*bearer\s+)[a-zA-Z0-9_\-\.]{15,}", r"\1[REDACTED_BEARER_TOKEN]"),
    (r"(?i)(authorization\s*:\s*basic\s+)[a-zA-Z0-9+/=]{10,}", r"\1[REDACTED_BASIC_AUTH]"),
    (r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{15,}", r"\1[REDACTED_TOKEN]"),
    
    # API Keys & Secrets
    (r"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key)(\s*[:=]\s*['\"]?)[a-zA-Z0-9_\-]{16,}(['\"]?)", r"\1\2[REDACTED_SECRET]\3"),
    (r"(?i)(sk-[a-zA-Z0-9_\-]{20,})", r"[REDACTED_API_KEY]"),
    (r"(?i)(ghp_[a-zA-Z0-9]{30,})", r"[REDACTED_GITHUB_TOKEN]"),
    
    # Cookie session identifiers
    (r"(?i)((?:phpsessid|jsessionid|sessionid|connect\.sid|laravel_session|_session|token|auth)\s*=\s*)[a-zA-Z0-9_\-\.]{10,}", r"\1[REDACTED_SESSION_COOKIE]"),
    
    # Passwords in URLs / queries / JSON (handling optional quotes around key)
    (r"(?i)(['\"]?(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?)[^&'\",\s\r\n]{3,}(['\"]?)", r"\1[REDACTED_PASSWORD]\2"),
    
    # Private Keys
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
    
    # Credit Card numbers & SSN patterns
    (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "[REDACTED_PAYMENT_CARD]"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
]


class SecuritySanitizer:
    """Sanitizes HTTP requests, responses, evidence, and payloads before LLM analysis."""

    @classmethod
    def sanitize_text(cls, text: str | None) -> str:
        if not text:
            return ""
        sanitized = text
        for pattern, replacement in _SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, replacement, sanitized)
        return sanitized

    @classmethod
    def sanitize_dict(cls, data: dict[str, Any]) -> dict[str, Any]:
        sanitized_data = {}
        for k, v in data.items():
            if isinstance(v, str):
                sanitized_data[k] = cls.sanitize_text(v)
            elif isinstance(v, dict):
                sanitized_data[k] = cls.sanitize_dict(v)
            elif isinstance(v, list):
                sanitized_data[k] = [
                    cls.sanitize_text(item) if isinstance(item, str)
                    else cls.sanitize_dict(item) if isinstance(item, dict)
                    else item
                    for item in v
                ]
            else:
                sanitized_data[k] = v
        return sanitized_data
