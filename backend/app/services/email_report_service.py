from __future__ import annotations

import asyncio
import email.utils
import html
import logging
import smtplib
from collections import Counter
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.session import AsyncSessionLocal
from app.models import Notification, Report, Scan, Target, User

logger = logging.getLogger("orion.email_reports")


class EmailReportService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.settings = get_settings()

    async def send_scan_report_email(self, scan_id: str, user_id: str, report_id: str | None = None) -> bool:
        """
        Sends the generated PDF security report for a completed scan to the authenticated,
        verified user's registered email address.
        
        Failure isolation: Errors are caught, logged without leaking secrets, and recorded
        in the Notification table. This method will NEVER raise an exception that could fail a scan.
        """
        if not getattr(self.settings, "email_reports_enabled", False):
            logger.debug("Automated email reports are disabled (email_reports_enabled=False). Skipping.")
            return False

        try:
            # 1. Tenant & Recipient Verification
            user_res = await self.db.execute(select(User).where(User.id == user_id))
            user = user_res.scalar_one_or_none()
            if not user or not user.is_active:
                logger.warning("User %s not found or inactive. Cannot send scan report email.", user_id)
                return False

            if not getattr(user, "is_verified", False):
                logger.info("User %s email is not verified. Skipping automated report email dispatch.", user.email)
                return False

            # 2. Scan Ownership Validation
            scan_res = await self.db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id))
            scan = scan_res.scalar_one_or_none()
            if not scan:
                logger.warning("Scan %s not found or does not belong to user %s. Aborting email dispatch.", scan_id, user_id)
                return False

            target_res = await self.db.execute(select(Target).where(Target.id == scan.target_id))
            target = target_res.scalar_one_or_none()
            target_url = target.url if target else (scan.current_url or "Target Host")

            # 3. Report Artifact Resolution
            report: Report | None = None
            if report_id:
                rep_res = await self.db.execute(select(Report).where(Report.id == report_id, Report.scan_id == scan.id))
                report = rep_res.scalar_one_or_none()
            if not report:
                rep_res = await self.db.execute(
                    select(Report)
                    .where(Report.scan_id == scan.id, Report.report_format == "pdf")
                    .order_by(Report.generated_at.desc())
                )
                report = rep_res.scalars().first()

            pdf_bytes: bytes | None = None
            pdf_filename = f"ORION_Security_Report_{scan.id[:8]}.pdf"
            if report and report.file_path:
                candidate_paths = [
                    Path(report.file_path),
                    Path("backend") / report.file_path,
                    Path(__file__).resolve().parent.parent.parent / report.file_path,
                    Path(__file__).resolve().parent.parent.parent / "backend" / report.file_path,
                ]
                resolved_pdf = next((p for p in candidate_paths if p.is_file()), None)
                if resolved_pdf:
                    pdf_bytes = resolved_pdf.read_bytes()
                    pdf_filename = resolved_pdf.name
                else:
                    logger.warning("PDF report path %s does not exist on disk for scan %s.", report.file_path, scan.id)

            # 4. Severity & Metrics Aggregation
            stats = scan.statistics_json or {}
            sev_dist: dict[str, int] = {}
            if report and isinstance(report.severity_distribution_json, dict):
                sev_dist = report.severity_distribution_json
            elif isinstance(stats.get("severity_distribution"), dict):
                sev_dist = stats["severity_distribution"]
            elif isinstance(stats.get("findings_by_severity"), dict):
                sev_dist = stats["findings_by_severity"]

            critical_count = int(sev_dist.get("critical", 0))
            high_count = int(sev_dist.get("high", 0))
            medium_count = int(sev_dist.get("medium", 0))
            low_count = int(sev_dist.get("low", 0))
            info_count = int(sev_dist.get("info", 0))
            total_findings = scan.total_findings or (critical_count + high_count + medium_count + low_count + info_count)
            risk_score = float(stats.get("overall_risk_score") or (report.overall_risk_score if report else 0.0) or 0.0)

            # 5. Email Composition (NO sensitive secrets, tokens, or headers)
            frontend_base = (self.settings.frontend_url or "https://orion-one-alpha.vercel.app").rstrip("/")
            secure_scan_url = f"{frontend_base}/scans/{scan.id}"
            completed_str = (
                scan.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if scan.completed_at
                else datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
            )

            subject = f"ORION Security Assessment Report — {target_url}"
            text_body = (
                f"ORION Automated Security Assessment\n"
                f"====================================\n\n"
                f"Target: {target_url}\n"
                f"Scan Type: {scan.scan_type or 'Standard'}\n"
                f"Status: {scan.status.title()}\n"
                f"Completed: {completed_str}\n"
                f"Overall Risk Score: {risk_score:.1f} / 100\n\n"
                f"Findings Summary (Total: {total_findings}):\n"
                f"- Critical: {critical_count}\n"
                f"- High:     {high_count}\n"
                f"- Medium:   {medium_count}\n"
                f"- Low:      {low_count}\n"
                f"- Info:     {info_count}\n\n"
                f"View complete interactive assessment in the ORION Security Desk:\n"
                f"{secure_scan_url}\n\n"
                f"{'Attached: Full PDF Security Report (' + pdf_filename + ')' if pdf_bytes else 'Report PDF can be downloaded directly from the dashboard.'}\n\n"
                f"--\nORION Autonomous Security Intelligence Platform"
            )

            safe_target = html.escape(str(target_url))
            safe_scan_type = html.escape(str(scan.scan_type or "Standard"))
            safe_user_name = html.escape(str(user.full_name or user.username or "Security Team"))

            html_body = f"""
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 620px; margin: 0 auto; background: #0b1120; color: #e2e8f0; border-radius: 12px; padding: 32px; border: 1px solid #1e293b; line-height: 1.6;">
              <div style="text-align: center; margin-bottom: 24px;">
                <h1 style="color: #38bdf8; font-size: 24px; margin: 0; letter-spacing: 2px;">ORION</h1>
                <p style="color: #94a3b8; font-size: 12px; margin: 4px 0 0; text-transform: uppercase; letter-spacing: 1.5px;">Security Assessment Completed</p>
              </div>

              <p style="font-size: 15px; color: #cbd5e1; margin-bottom: 20px;">
                Hello <strong>{safe_user_name}</strong>,
              </p>
              <p style="font-size: 14px; color: #94a3b8; margin-bottom: 24px;">
                The security assessment for <strong style="color: #f1f5f9;">{safe_target}</strong> has completed successfully.
              </p>

              <div style="background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 18px; margin-bottom: 24px;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px; color: #cbd5e1;">
                  <tr>
                    <td style="padding: 6px 0; color: #64748b;">Target:</td>
                    <td style="padding: 6px 0; font-weight: 600; text-align: right; color: #f8fafc;">{safe_target}</td>
                  </tr>
                  <tr>
                    <td style="padding: 6px 0; color: #64748b;">Scan Type:</td>
                    <td style="padding: 6px 0; text-align: right; color: #f8fafc;">{safe_scan_type}</td>
                  </tr>
                  <tr>
                    <td style="padding: 6px 0; color: #64748b;">Completed At:</td>
                    <td style="padding: 6px 0; text-align: right; color: #94a3b8;">{completed_str}</td>
                  </tr>
                  <tr>
                    <td style="padding: 6px 0; color: #64748b;">Overall Risk Score:</td>
                    <td style="padding: 6px 0; font-weight: bold; text-align: right; color: {'#ef4444' if risk_score >= 70 else '#f59e0b' if risk_score >= 40 else '#10b981'};">{risk_score:.1f} / 100</td>
                  </tr>
                </table>
              </div>

              <div style="margin-bottom: 24px;">
                <h3 style="font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; margin: 0 0 12px 0;">Severity Breakdown ({total_findings} Total)</h3>
                <div style="display: flex; gap: 8px;">
                  <table style="width: 100%; text-align: center; border-collapse: collapse; font-size: 12px;">
                    <tr>
                      <td style="background: #450a0a; color: #fca5a5; padding: 10px; border-radius: 6px; border: 1px solid #7f1d1d; width: 20%;">
                        <div style="font-size: 18px; font-weight: bold;">{critical_count}</div>
                        <div style="font-size: 10px; text-transform: uppercase;">Critical</div>
                      </td>
                      <td style="background: #431407; color: #fdba74; padding: 10px; border-radius: 6px; border: 1px solid #7c2d12; width: 20%;">
                        <div style="font-size: 18px; font-weight: bold;">{high_count}</div>
                        <div style="font-size: 10px; text-transform: uppercase;">High</div>
                      </td>
                      <td style="background: #422006; color: #fde047; padding: 10px; border-radius: 6px; border: 1px solid #713f12; width: 20%;">
                        <div style="font-size: 18px; font-weight: bold;">{medium_count}</div>
                        <div style="font-size: 10px; text-transform: uppercase;">Medium</div>
                      </td>
                      <td style="background: #064e3b; color: #6ee7b7; padding: 10px; border-radius: 6px; border: 1px solid #065f46; width: 20%;">
                        <div style="font-size: 18px; font-weight: bold;">{low_count}</div>
                        <div style="font-size: 10px; text-transform: uppercase;">Low</div>
                      </td>
                      <td style="background: #082f49; color: #7dd3fc; padding: 10px; border-radius: 6px; border: 1px solid #075985; width: 20%;">
                        <div style="font-size: 18px; font-weight: bold;">{info_count}</div>
                        <div style="font-size: 10px; text-transform: uppercase;">Info</div>
                      </td>
                    </tr>
                  </table>
                </div>
              </div>

              <div style="margin: 32px 0 24px; text-align: center;">
                <a href="{secure_scan_url}" style="background: #0ea5e9; color: #020817; font-weight: bold; text-decoration: none; padding: 12px 28px; border-radius: 6px; display: inline-block; font-size: 14px;">
                  View Live Security Report
                </a>
              </div>

              {f'<p style="font-size: 12px; color: #94a3b8; text-align: center; margin: 12px 0;">📎 The complete PDF assessment report (<strong>{html.escape(pdf_filename)}</strong>) is attached to this email.</p>' if pdf_bytes else ''}

              <p style="font-size: 11px; color: #475569; margin-top: 32px; border-top: 1px solid #1e293b; padding-top: 16px; text-align: center;">
                This automated notification was generated by ORION. To manage notification preferences, visit your account settings.
              </p>
            </div>
            """

            # 6. SMTP Transport Dispatch
            smtp_success = await self._dispatch_smtp(
                to_email=user.email,
                subject=subject,
                text_body=text_body,
                html_body=html_body,
                pdf_bytes=pdf_bytes,
                pdf_filename=pdf_filename,
            )

            # 7. Audit Notification Record
            try:
                notif = Notification(
                    user_id=user.id,
                    kind="scan_report_email" if smtp_success else "scan_report_email_failed",
                    title="Scan Report Delivered" if smtp_success else "Scan Report Email Failed",
                    message=(
                        f"Security report for {target_url} was successfully emailed to {user.email}."
                        if smtp_success
                        else f"Unable to email report for {target_url} to {user.email}."
                    ),
                    payload_json={
                        "scan_id": scan.id,
                        "target_url": target_url,
                        "report_id": report.id if report else None,
                        "has_pdf": pdf_bytes is not None,
                        "delivered": smtp_success,
                        "to_email": user.email,
                        "timestamp": datetime.now(UTC).isoformat(),
                    },
                )
                self.db.add(notif)
                await self.db.commit()
            except Exception as notif_err:
                logger.warning("Failed to persist email delivery notification: %s", notif_err)

            return smtp_success

        except Exception as exc:
            logger.error("Unexpected error in scan report email delivery for scan %s: %s", scan_id, exc)
            return False

    async def _dispatch_smtp(
        self,
        to_email: str,
        subject: str,
        text_body: str,
        html_body: str | None = None,
        pdf_bytes: bytes | None = None,
        pdf_filename: str = "report.pdf",
    ) -> bool:
        """Sends email via configured SMTP without leaking credentials on error."""
        if not self.settings.smtp_host or not self.settings.smtp_from_email:
            logger.info("SMTP host or sender email not configured. Skipping email dispatch.")
            return False

        sender_name = getattr(self.settings, "smtp_from_name", "ORION Security")
        from_header = email.utils.formataddr((sender_name, self.settings.smtp_from_email))

        def _send() -> None:
            message = EmailMessage()
            message["Subject"] = subject
            message["From"] = from_header
            message["To"] = to_email
            message.set_content(text_body)

            if html_body:
                message.add_alternative(html_body, subtype="html")

            if pdf_bytes:
                message.add_attachment(
                    pdf_bytes,
                    maintype="application",
                    subtype="pdf",
                    filename=pdf_filename,
                )

            port = int(self.settings.smtp_port or 587)
            if port == 465:
                with smtplib.SMTP_SSL(self.settings.smtp_host, port, timeout=20) as smtp:
                    if self.settings.smtp_username and self.settings.smtp_password:
                        smtp.login(self.settings.smtp_username, self.settings.smtp_password)
                    smtp.send_message(message)
            else:
                with smtplib.SMTP(self.settings.smtp_host, port, timeout=20) as smtp:
                    smtp.starttls()
                    if self.settings.smtp_username and self.settings.smtp_password:
                        smtp.login(self.settings.smtp_username, self.settings.smtp_password)
                    smtp.send_message(message)

        try:
            await asyncio.to_thread(_send)
            logger.info("Scan report email successfully dispatched to %s", to_email)
            return True
        except Exception as exc:
            # Explicitly sanitize error message to prevent accidental credential leakage
            logger.error(
                "Failed to send scan report email to %s via SMTP (%s:%s): %s",
                to_email,
                self.settings.smtp_host,
                self.settings.smtp_port,
                type(exc).__name__,
            )
            return False

    @classmethod
    async def send_scan_report_email_bg(cls, scan_id: str, user_id: str, report_id: str | None = None) -> bool:
        """Background helper for async non-celery execution with independent DB session."""
        try:
            async with AsyncSessionLocal() as session:
                service = cls(session)
                return await service.send_scan_report_email(scan_id, user_id, report_id)
        except Exception as exc:
            logger.error("Background scan report email task error for scan %s: %s", scan_id, exc)
            return False
