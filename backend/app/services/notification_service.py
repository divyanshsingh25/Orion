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
        subject = f"Your ORION Verification OTP: {token}"
        base_url = (self.settings.frontend_url or "http://localhost:5173").rstrip("/")
        verification_link = f"{base_url}/verify-email?token={token}&email={user.email}"
        text_body = (
            f"Hello {user.full_name or user.username},\n\n"
            f"Thank you for registering with ORION.\n\n"
            f"Your One-Time Passcode (OTP) is:\n\n"
            f"    {token}\n\n"
            f"Enter this 6-digit code on the verification screen to activate your account.\n\n"
            f"Or click this link to verify your account automatically:\n{verification_link}\n\n"
            f"This code will expire in 24 hours. If you did not request this, please ignore this email."
        )
        html_body = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 580px; margin: 0 auto; background: #0b1120; color: #f8fafc; border-radius: 12px; padding: 32px; border: 1px solid #1e293b;">
          <div style="text-align: center; margin-bottom: 24px;">
            <h1 style="color: #38bdf8; font-size: 26px; margin: 0; letter-spacing: 2px;">ORION</h1>
            <p style="color: #94a3b8; font-size: 12px; margin: 4px 0 0; text-transform: uppercase; letter-spacing: 1.5px;">Account Verification</p>
          </div>
          <p style="font-size: 15px; line-height: 1.6; color: #cbd5e1;">
            Hello <strong>{user.full_name or user.username}</strong>,
          </p>
          <p style="font-size: 14px; line-height: 1.6; color: #94a3b8;">
            Please enter the following 6-digit One-Time Passcode (OTP) to verify your registered email address and activate your ORION security desk:
          </p>
          <div style="margin: 28px 0; text-align: center;">
            <div style="background: #0f172a; border: 1px solid #0284c7; border-radius: 10px; padding: 18px 28px; display: inline-block; box-shadow: 0 4px 12px rgba(2,132,199,0.15);">
              <span style="font-family: 'Courier New', Courier, monospace; font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #38bdf8; user-select: all;">{token}</span>
            </div>
            <p style="font-size: 12px; color: #64748b; margin-top: 10px;">One-Time Passcode (Valid for 24 hours)</p>
          </div>
          <div style="margin: 24px 0; text-align: center;">
            <p style="font-size: 13px; color: #94a3b8; margin-bottom: 12px;">Or verify automatically with a single click:</p>
            <a href="{verification_link}" style="background: #0ea5e9; color: #020817; font-weight: bold; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block; font-size: 14px;">
              Verify Email Automatically
            </a>
          </div>
          <p style="font-size: 11px; color: #475569; margin-top: 32px; border-top: 1px solid #1e293b; padding-top: 16px; text-align: center;">
            If you did not request this email, please ignore it. Never share your OTP with anyone.
          </p>
        </div>
        """
        logger.info("Email verification OTP generated for user %s (%s): %s", user.username, user.email, token)
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
        import email.utils

        sender_name = getattr(self.settings, "smtp_from_name", "ORION Security")
        from_header = email.utils.formataddr((sender_name, self.settings.smtp_from_email))
        smtp_pwd = (self.settings.smtp_password or "").replace(" ", "") if self.settings.smtp_password else None

        def _send():
            message = EmailMessage()
            message["Subject"] = subject
            message["From"] = from_header
            message["To"] = to_email
            message.set_content(body)
            if html_body:
                message.add_alternative(html_body, subtype="html")

            port = int(self.settings.smtp_port or 587)
            if port == 465:
                with smtplib.SMTP_SSL(self.settings.smtp_host, port, timeout=15) as smtp:
                    if self.settings.smtp_username and smtp_pwd:
                        smtp.login(self.settings.smtp_username, smtp_pwd)
                    smtp.send_message(message)
            else:
                with smtplib.SMTP(self.settings.smtp_host, port, timeout=15) as smtp:
                    smtp.starttls()
                    if self.settings.smtp_username and smtp_pwd:
                        smtp.login(self.settings.smtp_username, smtp_pwd)
                    smtp.send_message(message)

        try:
            await asyncio.to_thread(_send)
            logger.info("Email successfully dispatched to %s", to_email)
        except Exception as exc:
            logger.error(
                "Failed to send email to %s via SMTP (%s:%s): %s",
                to_email,
                self.settings.smtp_host,
                self.settings.smtp_port,
                type(exc).__name__,
            )
