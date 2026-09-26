"""
Email Transport Module for ORION.
Supports Resend HTTPS API (port 443) and SMTP fallback.
"""
from __future__ import annotations

import base64
import logging
import re
from typing import Any

import httpx

from app.core.config import Settings

logger = logging.getLogger("orion.email")

RESEND_API_URL = "https://api.resend.com/emails"


def sanitize_error_message(msg: str, secrets: list[str | None] | None = None) -> str:
    """Removes sensitive credentials, keys, OTPs, and tokens from error messages."""
    sanitized = str(msg)
    # Redact Bearer tokens in Authorization headers or text
    sanitized = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer [REDACTED]", sanitized, flags=re.IGNORECASE)
    # Redact Resend API keys (re_...)
    sanitized = re.sub(r"re_[A-Za-z0-9_\-]+", "re_[REDACTED]", sanitized)
    if secrets:
        for secret in secrets:
            if secret and str(secret).strip() and len(str(secret).strip()) >= 4 and str(secret) in sanitized:
                sanitized = sanitized.replace(str(secret), "[REDACTED]")
    return sanitized


async def send_email_via_resend(
    settings: Settings,
    to_email: str,
    subject: str,
    text_body: str,
    html_body: str | None = None,
    pdf_bytes: bytes | None = None,
    pdf_filename: str = "report.pdf",
) -> bool:
    """
    Sends an email via Resend's official HTTPS REST API (port 443).
    Fully asynchronous using httpx.AsyncClient.
    Safe against credential, OTP, token, or key leakage in logs.
    """
    api_key = settings.resend_api_key
    if not api_key:
        logger.error("Resend API key not configured (ORION_RESEND_API_KEY is missing). Skipping email dispatch.")
        return False

    sender_name = getattr(settings, "smtp_from_name", "ORION Security")
    from_email = settings.email_from or settings.smtp_from_email or "onboarding@resend.dev"
    from_address = f"{sender_name} <{from_email}>" if sender_name else from_email

    payload: dict[str, Any] = {
        "from": from_address,
        "to": [to_email],
        "subject": subject,
        "text": text_body,
    }
    if html_body:
        payload["html"] = html_body

    if pdf_bytes:
        payload["attachments"] = [
            {
                "filename": pdf_filename,
                "content": base64.b64encode(pdf_bytes).decode("ascii"),
            }
        ]

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "ORION-Security/1.0",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                RESEND_API_URL,
                json=payload,
                headers=headers,
            )

        if response.status_code in (200, 201):
            try:
                res_data = response.json()
                email_id = res_data.get("id", "dispatched")
            except Exception:
                email_id = "dispatched"
            logger.info("Email successfully dispatched to %s via Resend HTTPS API (id: %s)", to_email, email_id)
            return True

        # Handle non-2xx API error response safely
        error_name = "api_error"
        error_detail = response.text
        try:
            err_json = response.json()
            error_name = err_json.get("name", "api_error")
            error_detail = err_json.get("message", response.text)
        except Exception:
            pass

        sanitized_detail = sanitize_error_message(error_detail, [api_key])
        logger.error(
            "Failed to send email to %s via Resend HTTPS API (HTTP %s, %s): %s",
            to_email,
            response.status_code,
            error_name,
            sanitized_detail,
        )
        return False

    except httpx.TimeoutException:
        logger.error("Resend API timed out while sending email to %s", to_email)
        return False
    except httpx.RequestError as exc:
        exc_type = type(exc).__name__
        sanitized_err = sanitize_error_message(str(exc), [api_key])
        logger.error(
            "Resend API network error sending email to %s (%s): %s",
            to_email,
            exc_type,
            sanitized_err,
        )
        return False
    except Exception as exc:
        exc_type = type(exc).__name__
        sanitized_err = sanitize_error_message(str(exc), [api_key])
        logger.error(
            "Unexpected error sending email to %s via Resend (%s): %s",
            to_email,
            exc_type,
            sanitized_err,
        )
        return False
