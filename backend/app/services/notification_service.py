import logging
import smtplib
from email.message import EmailMessage
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import Notification, User

logger = logging.getLogger("orion.notifications")


class NotificationService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.settings = get_settings()

    async def create_notification(self, user: User, kind: str, title: str, message: str, payload: dict[str, Any] | None = None) -> Notification:
        notification = Notification(user_id=user.id, kind=kind, title=title, message=message, payload_json=payload)
        self.db.add(notification)
        await self.db.flush()
        return notification

    async def send_verification_email(self, user: User, token: str) -> None:
        subject = "Verify your ORION account"
        base_url = (self.settings.frontend_url or "http://localhost:5173").rstrip("/")
        verification_link = f"{base_url}/verify-email?token={token}&email={user.email}"
        text_body = (
            f"Hello {user.full_name or user.username},\n\n"
            f"Thank you for registering with ORION.\n\n"
            f"Your verification code is:\n{token}\n\n"
            f"Or click this link to verify your account automatically:\n{verification_link}\n\n"
            f"If you did not request this, please ignore this email."
        )
        html_body = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; background: #020817; color: #f8fafc; border-radius: 12px; padding: 32px; border: 1px solid #1e293b;">
          <div style="text-align: center; margin-bottom: 24px;">
            <h1 style="color: #38bdf8; font-size: 26px; margin: 0; letter-spacing: 2px;">ORION</h1>
            <p style="color: #94a3b8; font-size: 12px; margin: 4px 0 0; text-transform: uppercase; letter-spacing: 1.5px;">Account Verification</p>
          </div>
          <p style="font-size: 15px; line-height: 1.6; color: #cbd5e1;">
            Hello <strong>{user.full_name or user.username}</strong>,
          </p>
          <p style="font-size: 15px; line-height: 1.6; color: #cbd5e1;">
            Please verify your email address to complete your registration and activate your ORION security desk.
          </p>
          <div style="margin: 28px 0; text-align: center;">
            <a href="{verification_link}" style="background: #06b6d4; color: #020817; font-weight: bold; text-decoration: none; padding: 14px 28px; border-radius: 8px; display: inline-block; font-size: 15px;">
              Verify Email Address
            </a>
          </div>
          <div style="background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin: 24px 0;">
            <p style="margin: 0 0 6px; font-size: 12px; color: #94a3b8; text-transform: uppercase;">Or enter this code manually:</p>
            <code style="font-family: monospace; font-size: 16px; color: #38bdf8; word-break: break-all;">{token}</code>
          </div>
          <p style="font-size: 12px; color: #64748b; margin-top: 32px; border-top: 1px solid #1e293b; padding-top: 16px;">
            If you did not request this email, no further action is required.
          </p>
        </div>
        """
        logger.info("Email verification token generated for user %s (%s): %s", user.username, user.email, token)
        await self.create_notification(user, "email_verification", subject, text_body, {"token": token})
        await self._maybe_send_email(user.email, subject, text_body, html_body)

    async def send_password_reset_email(self, user: User, token: str) -> None:
        subject = "Reset your ORION password"
        base_url = (self.settings.frontend_url or "http://localhost:5173").rstrip("/")
        reset_link = f"{base_url}/reset-password?token={token}"
        text_body = f"Use this password reset token: {token}\n\nOr click: {reset_link}"
        logger.info("Password reset token generated for user %s (%s): %s", user.username, user.email, token)
        await self.create_notification(user, "password_reset", subject, text_body, {"token": token})
        await self._maybe_send_email(user.email, subject, text_body)

    async def _maybe_send_email(self, to_email: str, subject: str, body: str, html_body: str | None = None) -> None:
        if not self.settings.smtp_host or not self.settings.smtp_from_email:
            logger.info("SMTP not configured. Skipping external email dispatch.")
            return

        import asyncio

        def _send():
            message = EmailMessage()
            message["Subject"] = subject
            message["From"] = self.settings.smtp_from_email
            message["To"] = to_email
            message.set_content(body)
            if html_body:
                message.add_alternative(html_body, subtype="html")

            port = int(self.settings.smtp_port or 587)
            if port == 465:
                with smtplib.SMTP_SSL(self.settings.smtp_host, port, timeout=15) as smtp:
                    if self.settings.smtp_username and self.settings.smtp_password:
                        smtp.login(self.settings.smtp_username, self.settings.smtp_password)
                    smtp.send_message(message)
            else:
                with smtplib.SMTP(self.settings.smtp_host, port, timeout=15) as smtp:
                    smtp.starttls()
                    if self.settings.smtp_username and self.settings.smtp_password:
                        smtp.login(self.settings.smtp_username, self.settings.smtp_password)
                    smtp.send_message(message)

        try:
            await asyncio.to_thread(_send)
            logger.info("Email successfully dispatched to %s", to_email)
        except Exception as exc:
            logger.error("Failed to send email to %s via SMTP (%s:%s): %s", to_email, self.settings.smtp_host, self.settings.smtp_port, exc)
