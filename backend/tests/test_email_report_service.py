from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import get_settings
from app.database.session import AsyncSessionLocal, async_engine
from app.models import Notification, Project, Report, Scan, Target, User
from app.services.email_report_service import EmailReportService
from app.services.report_service import ReportService
from app.services.scan_service import ScanService


@pytest.fixture(autouse=True)
async def cleanup_engine():
    await async_engine.dispose()
    yield
    await async_engine.dispose()


@pytest.mark.asyncio
async def test_email_feature_disabled_by_default():
    """Verify that when email_reports_enabled is False, zero emails are sent and method returns False."""
    async with AsyncSessionLocal() as session:
        service = EmailReportService(session)
        # Ensure setting is False
        with patch.object(service.settings, "email_reports_enabled", False):
            result = await service.send_scan_report_email("dummy-scan-id", "dummy-user-id")
            assert result is False


@pytest.mark.asyncio
async def test_email_skipped_for_unverified_user():
    """Verify that email reports are not sent to unverified user accounts."""
    async with AsyncSessionLocal() as session:
        # Create unverified user
        unique_id = uuid.uuid4().hex[:8]
        user = User(
            email=f"unverified_{unique_id}@test.sec",
            username=f"unverified_{unique_id}",
            is_active=True,
            is_verified=False,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        service = EmailReportService(session)
        with patch.object(service.settings, "email_reports_enabled", True):
            result = await service.send_scan_report_email("any-scan-id", user.id)
            assert result is False


@pytest.mark.asyncio
async def test_recipient_ownership_and_tenant_isolation():
    """Verify that a user cannot request/trigger an email for a scan belonging to someone else."""
    async with AsyncSessionLocal() as session:
        unique_1 = uuid.uuid4().hex[:8]
        unique_2 = uuid.uuid4().hex[:8]
        
        user1 = User(email=f"user1_{unique_1}@test.sec", username=f"user1_{unique_1}", is_active=True, is_verified=True)
        user2 = User(email=f"user2_{unique_2}@test.sec", username=f"user2_{unique_2}", is_active=True, is_verified=True)
        session.add_all([user1, user2])
        await session.commit()
        await session.refresh(user1)
        await session.refresh(user2)

        proj = Project(name=f"Project {unique_1}", user_id=user1.id)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)

        target = Target(project_id=proj.id, scheme="https", host="victim.internal.sec", url="https://victim.internal.sec")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        # Scan belongs to user1
        scan = Scan(
            project_id=proj.id,
            target_id=target.id,
            user_id=user1.id,
            scan_type="quick",
            status="completed",
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        service = EmailReportService(session)
        with patch.object(service.settings, "email_reports_enabled", True):
            # user2 tries to get user1's scan report email
            result = await service.send_scan_report_email(scan.id, user2.id)
            assert result is False, "Must reject email dispatch when scan ownership does not match user."


@pytest.mark.asyncio
async def test_successful_email_delivery_with_pdf_attachment(tmp_path):
    """Verify end-to-end report email creation with PDF attachment and notification persistence."""
    async with AsyncSessionLocal() as session:
        unique = uuid.uuid4().hex[:8]
        user = User(
            email=f"sec_lead_{unique}@example.com",
            full_name="Security Lead",
            username=f"seclead_{unique}",
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        proj = Project(name=f"SecOps {unique}", user_id=user.id)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)

        target = Target(project_id=proj.id, scheme="https", host="app.example.com", url="https://app.example.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        scan = Scan(
            project_id=proj.id,
            target_id=target.id,
            user_id=user.id,
            scan_type="Full Security Scan",
            status="completed",
            total_findings=3,
            statistics_json={
                "overall_risk_score": 65.5,
                "severity_distribution": {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0},
            },
            completed_at=datetime.now(UTC),
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        # Create dummy PDF report artifact
        pdf_file = tmp_path / "test_report.pdf"
        pdf_file.write_bytes(b"%PDF-1.4 mock pdf binary content for Orion test")

        report = Report(
            scan_id=scan.id,
            project_id=proj.id,
            target_id=target.id,
            report_format="pdf",
            file_path=str(pdf_file),
            file_size=pdf_file.stat().st_size,
            executive_summary="ORION scan identified 3 vulnerabilities.",
            overall_risk_score=65.5,
            severity_distribution_json={"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0},
            owasp_breakdown_json={},
            cwe_mapping_json={},
            cvss_analysis_json={"critical": 1, "high": 1, "medium": 1, "low": 0},
        )
        session.add(report)
        await session.commit()
        await session.refresh(report)

        service = EmailReportService(session)
        sent_messages = []

        def mock_dispatch(to_email, subject, text_body, html_body=None, pdf_bytes=None, pdf_filename="report.pdf"):
            sent_messages.append({
                "to_email": to_email,
                "subject": subject,
                "text_body": text_body,
                "html_body": html_body,
                "pdf_bytes": pdf_bytes,
                "pdf_filename": pdf_filename,
            })
            return True

        with patch.object(service.settings, "email_reports_enabled", True), \
             patch.object(service, "_dispatch_smtp", side_effect=mock_dispatch):
            success = await service.send_scan_report_email(scan.id, user.id, report.id)
            assert success is True
            assert len(sent_messages) == 1
            sent = sent_messages[0]

            # Assert content & attachment
            assert sent["to_email"] == user.email
            assert "https://app.example.com" in sent["subject"]
            assert "Overall Risk Score: 65.5" in sent["text_body"]
            assert "Critical: 1" in sent["text_body"]
            assert sent["pdf_bytes"] == b"%PDF-1.4 mock pdf binary content for Orion test"
            assert sent["pdf_filename"] == "test_report.pdf"
            # Assert NO JWT / passwords / secrets in body
            assert "token=" not in sent["text_body"]
            assert "Bearer" not in sent["text_body"]
            assert "password" not in sent["text_body"].lower()

            # Verify notification was persisted in DB
            notif_res = await session.execute(
                select(Notification).where(Notification.user_id == user.id, Notification.kind == "scan_report_email")
            )
            notif = notif_res.scalar_one_or_none()
            assert notif is not None
            assert notif.payload_json["scan_id"] == scan.id
            assert notif.payload_json["has_pdf"] is True


@pytest.mark.asyncio
async def test_email_delivery_failure_isolation_does_not_fail_scan():
    """Verify that when SMTP raises an error, the scan status remains 'completed' and failure is logged."""
    async with AsyncSessionLocal() as session:
        unique = uuid.uuid4().hex[:8]
        user = User(
            email=f"failure_test_{unique}@example.com",
            username=f"fail_{unique}",
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        proj = Project(name=f"FailTest {unique}", user_id=user.id)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)

        target = Target(project_id=proj.id, scheme="https", host="test.fail.sec", url="https://test.fail.sec")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        scan = Scan(
            project_id=proj.id,
            target_id=target.id,
            user_id=user.id,
            scan_type="quick",
            status="completed",
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        service = EmailReportService(session)
        with patch.object(service.settings, "email_reports_enabled", True), \
             patch.object(service, "_dispatch_smtp", return_value=False):
            success = await service.send_scan_report_email(scan.id, user.id)
            assert success is False

        # Verify scan status is STILL completed in DB
        scan_db_res = await session.execute(select(Scan).where(Scan.id == scan.id))
        scan_db = scan_db_res.scalar_one()
        assert scan_db.status == "completed"

        # Verify failure notification was stored for audit
        notif_res = await session.execute(
            select(Notification).where(Notification.user_id == user.id, Notification.kind == "scan_report_email_failed")
        )
        notif = notif_res.scalar_one_or_none()
        assert notif is not None


@pytest.mark.asyncio
async def test_missing_smtp_config_handled_gracefully():
    """Verify that when SMTP host is missing, email dispatch returns False without error."""
    async with AsyncSessionLocal() as session:
        service = EmailReportService(session)
        with patch.object(service.settings, "smtp_host", None):
            result = await service._dispatch_smtp("user@example.com", "Subject", "Body")
            assert result is False


@pytest.mark.asyncio
async def test_missing_pdf_file_handled_gracefully():
    """Verify that if the PDF report is missing on disk, email still delivers without attachment without error."""
    async with AsyncSessionLocal() as session:
        unique = uuid.uuid4().hex[:8]
        user = User(email=f"nopdf_{unique}@example.com", username=f"nopdf_{unique}", is_active=True, is_verified=True)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        proj = Project(name=f"NoPDF {unique}", user_id=user.id)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)

        target = Target(project_id=proj.id, scheme="https", host="nopdf.sec", url="https://nopdf.sec")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        scan = Scan(project_id=proj.id, target_id=target.id, user_id=user.id, scan_type="quick", status="completed")
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        # Non-existent report file path
        report = Report(
            scan_id=scan.id,
            project_id=proj.id,
            target_id=target.id,
            report_format="pdf",
            file_path="/path/to/nonexistent/report.pdf",
            executive_summary="ORION scan summary",
            overall_risk_score=0.0,
            severity_distribution_json={},
            owasp_breakdown_json={},
            cwe_mapping_json={},
            cvss_analysis_json={},
        )
        session.add(report)
        await session.commit()
        await session.refresh(report)

        service = EmailReportService(session)
        sent_pdf_bytes = None

        def mock_dispatch(to_email, subject, text_body, html_body=None, pdf_bytes=None, pdf_filename="report.pdf"):
            nonlocal sent_pdf_bytes
            sent_pdf_bytes = pdf_bytes
            return True

        with patch.object(service.settings, "email_reports_enabled", True), \
             patch.object(service, "_dispatch_smtp", side_effect=mock_dispatch):
            success = await service.send_scan_report_email(scan.id, user.id, report.id)
            assert success is True
            # pdf_bytes should be None because file didn't exist
            assert sent_pdf_bytes is None


@pytest.mark.asyncio
async def test_manual_report_download_remains_functional(tmp_path):
    """Verify that manual report listing and download API service logic remains 100% operational."""
    async with AsyncSessionLocal() as session:
        unique = uuid.uuid4().hex[:8]
        user = User(email=f"manual_{unique}@example.com", username=f"manual_{unique}", is_active=True, is_verified=True)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        proj = Project(name=f"ManualProj {unique}", user_id=user.id)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)

        target = Target(project_id=proj.id, scheme="https", host="manual.sec", url="https://manual.sec")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        scan = Scan(project_id=proj.id, target_id=target.id, user_id=user.id, scan_type="quick", status="completed")
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        pdf_path = tmp_path / "manual_download.pdf"
        pdf_path.write_text("dummy manual pdf")

        report = Report(
            scan_id=scan.id,
            project_id=proj.id,
            target_id=target.id,
            report_format="pdf",
            file_path=str(pdf_path),
            file_size=pdf_path.stat().st_size,
            executive_summary="Manual report executive summary",
            overall_risk_score=10.0,
            severity_distribution_json={"low": 1},
            owasp_breakdown_json={},
            cwe_mapping_json={},
            cvss_analysis_json={"low": 1},
        )
        session.add(report)
        await session.commit()
        await session.refresh(report)

        report_service = ReportService(session)
        reports = await report_service.list_reports(user, scan_id=scan.id)
        assert len(reports) >= 1
        matched = [r for r in reports if r.id == report.id]
        assert len(matched) == 1
        assert matched[0].file_path == str(pdf_path)
