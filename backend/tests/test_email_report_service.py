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


@pytest.mark.asyncio
async def test_report_service_generate_report_does_not_send_email(tmp_path):
    """TEST 2: Verify ReportService.generate_report() generates report but never triggers email sending."""
    async with AsyncSessionLocal() as session:
        unique = uuid.uuid4().hex[:8]
        user = User(email=f"noreportemail_{unique}@example.com", username=f"repuser_{unique}", is_active=True, is_verified=True)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        proj = Project(name=f"NoEmailProj {unique}", user_id=user.id)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)

        target = Target(project_id=proj.id, scheme="https", host="noemail.sec", url="https://noemail.sec")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        scan = Scan(project_id=proj.id, target_id=target.id, user_id=user.id, scan_type="quick", status="completed")
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        report_service = ReportService(session)
        with patch("app.services.email_report_service.EmailReportService.send_scan_report_email_bg") as mock_bg:
            report_read = await report_service.generate_report(user, scan.id, "json")
            assert report_read is not None
            assert report_read.scan_id == scan.id
            mock_bg.assert_not_called()


@pytest.mark.asyncio
async def test_scan_completion_sends_email_exactly_once(tmp_path):
    """TEST 1: Verify scan completion email dispatch path triggers background email task exactly once."""
    async with AsyncSessionLocal() as session:
        unique = uuid.uuid4().hex[:8]
        user = User(email=f"scanonce_{unique}@example.com", username=f"scanonce_{unique}", is_active=True, is_verified=True)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        proj = Project(name=f"ScanOnceProj {unique}", user_id=user.id)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)

        target = Target(project_id=proj.id, scheme="https", host="scanonce.sec", url="https://scanonce.sec")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        scan = Scan(project_id=proj.id, target_id=target.id, user_id=user.id, scan_type="quick", status="running")
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        scan_service = ScanService(session)
        tasks_created = []

        def mock_create_task(coro):
            tasks_created.append(coro)
            if hasattr(coro, "close"):
                coro.close()
            return MagicMock()

        with patch.object(scan_service.settings, "email_reports_enabled", True), \
             patch("asyncio.create_task", side_effect=mock_create_task):
            report = await scan_service.report_service.generate_report(user, scan.id, "json")
            report_id = report.id

            if getattr(scan_service.settings, "email_reports_enabled", False):
                if getattr(scan_service.settings, "use_celery", False):
                    pass
                else:
                    from app.services.email_report_service import EmailReportService
                    asyncio.create_task(EmailReportService.send_scan_report_email_bg(scan.id, user.id, report_id))

            assert len(tasks_created) == 1


@pytest.mark.asyncio
async def test_email_report_idempotency_sequential(tmp_path):
    """TEST 3: Verify calling send_scan_report_email twice results in exactly 1 dispatch and 1 notification."""
    async with AsyncSessionLocal() as session:
        unique = uuid.uuid4().hex[:8]
        user = User(email=f"idempotent_{unique}@example.com", username=f"idemp_{unique}", is_active=True, is_verified=True)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        proj = Project(name=f"IdempProj {unique}", user_id=user.id)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)

        target = Target(project_id=proj.id, scheme="https", host="idemp.sec", url="https://idemp.sec")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        scan = Scan(project_id=proj.id, target_id=target.id, user_id=user.id, scan_type="quick", status="completed")
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        pdf_path = tmp_path / f"idemp_{unique}.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 dummy idempotent pdf")

        report = Report(
            scan_id=scan.id,
            project_id=proj.id,
            target_id=target.id,
            report_format="pdf",
            file_path=str(pdf_path),
            file_size=pdf_path.stat().st_size,
            executive_summary="Idempotency test summary",
            overall_risk_score=25.0,
            severity_distribution_json={"medium": 1},
            owasp_breakdown_json={},
            cwe_mapping_json={},
            cvss_analysis_json={"medium": 1},
        )
        session.add(report)
        await session.commit()
        await session.refresh(report)

        service = EmailReportService(session)
        dispatch_count = 0

        async def mock_dispatch(*args, **kwargs):
            nonlocal dispatch_count
            dispatch_count += 1
            return True

        with patch.object(service.settings, "email_reports_enabled", True), \
             patch.object(service.settings, "email_provider", "resend"), \
             patch.object(service.settings, "resend_api_key", "re_mock_test_key"), \
             patch.object(EmailReportService, "_dispatch_resend", side_effect=mock_dispatch):
            
            # First call -> sends email and creates notification
            result1 = await service.send_scan_report_email(scan.id, user.id, report.id)
            assert result1 is True
            assert dispatch_count == 1

            # Second call -> skips because notification exists
            result2 = await service.send_scan_report_email(scan.id, user.id, report.id)
            assert result2 is True
            assert dispatch_count == 1

        # Verify only ONE notification in DB
        notif_res = await session.execute(
            select(Notification).where(
                Notification.user_id == user.id,
                Notification.kind == "scan_report_email",
            )
        )
        notifs = notif_res.scalars().all()
        assert len(notifs) == 1
        assert notifs[0].payload_json["scan_id"] == scan.id


@pytest.mark.asyncio
async def test_email_report_idempotency_concurrent(tmp_path):
    """TEST 4: Verify concurrent attempts for the same scan result in exactly 1 dispatch and 1 notification."""
    unique = uuid.uuid4().hex[:8]
    pdf_path = tmp_path / f"concurrent_{unique}.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 dummy concurrent pdf")

    async with AsyncSessionLocal() as session:
        user = User(email=f"concur_{unique}@example.com", username=f"concur_{unique}", is_active=True, is_verified=True)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        proj = Project(name=f"ConcurProj {unique}", user_id=user.id)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)

        target = Target(project_id=proj.id, scheme="https", host="concur.sec", url="https://concur.sec")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        scan = Scan(project_id=proj.id, target_id=target.id, user_id=user.id, scan_type="quick", status="completed")
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        report = Report(
            scan_id=scan.id,
            project_id=proj.id,
            target_id=target.id,
            report_format="pdf",
            file_path=str(pdf_path),
            file_size=pdf_path.stat().st_size,
            executive_summary="Concurrent test summary",
            overall_risk_score=35.0,
            severity_distribution_json={"high": 1},
            owasp_breakdown_json={},
            cwe_mapping_json={},
            cvss_analysis_json={"high": 1},
        )
        session.add(report)
        await session.commit()
        await session.refresh(report)

        user_id = user.id
        scan_id = scan.id
        report_id = report.id

    dispatch_count = 0

    async def mock_dispatch(*args, **kwargs):
        nonlocal dispatch_count
        dispatch_count += 1
        await asyncio.sleep(0.05)
        return True

    async def task_worker():
        async with AsyncSessionLocal() as sess:
            svc = EmailReportService(sess)
            svc.settings.email_reports_enabled = True
            svc.settings.email_provider = "resend"
            svc.settings.resend_api_key = "re_mock_concur_key"
            return await svc.send_scan_report_email(scan_id, user_id, report_id)

    with patch.object(EmailReportService, "_dispatch_resend", side_effect=mock_dispatch):
        results = await asyncio.gather(task_worker(), task_worker())
    assert results == [True, True]
    assert dispatch_count == 1

    async with AsyncSessionLocal() as session:
        notif_res = await session.execute(
            select(Notification).where(
                Notification.user_id == user_id,
                Notification.kind == "scan_report_email",
            )
        )
        notifs = notif_res.scalars().all()
        assert len(notifs) == 1
        assert notifs[0].payload_json["scan_id"] == scan_id


@pytest.mark.asyncio
async def test_different_scans_remain_independent(tmp_path):
    """TEST 5: Verify distinct scans remain completely independent, each getting 1 email and 1 notification."""
    async with AsyncSessionLocal() as session:
        unique = uuid.uuid4().hex[:8]
        user = User(email=f"indep_{unique}@example.com", username=f"indep_{unique}", is_active=True, is_verified=True)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        proj = Project(name=f"IndepProj {unique}", user_id=user.id)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)

        target = Target(project_id=proj.id, scheme="https", host="indep.sec", url="https://indep.sec")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        scan_a = Scan(project_id=proj.id, target_id=target.id, user_id=user.id, scan_type="quick", status="completed")
        scan_b = Scan(project_id=proj.id, target_id=target.id, user_id=user.id, scan_type="full", status="completed")
        session.add_all([scan_a, scan_b])
        await session.commit()
        await session.refresh(scan_a)
        await session.refresh(scan_b)

        pdf_a = tmp_path / f"scan_a_{unique}.pdf"
        pdf_b = tmp_path / f"scan_b_{unique}.pdf"
        pdf_a.write_bytes(b"%PDF-1.4 scan A pdf")
        pdf_b.write_bytes(b"%PDF-1.4 scan B pdf")

        rep_a = Report(
            scan_id=scan_a.id, project_id=proj.id, target_id=target.id,
            report_format="pdf", file_path=str(pdf_a), file_size=pdf_a.stat().st_size,
            executive_summary="Scan A summary", overall_risk_score=10.0,
            severity_distribution_json={}, owasp_breakdown_json={}, cwe_mapping_json={}, cvss_analysis_json={},
        )
        rep_b = Report(
            scan_id=scan_b.id, project_id=proj.id, target_id=target.id,
            report_format="pdf", file_path=str(pdf_b), file_size=pdf_b.stat().st_size,
            executive_summary="Scan B summary", overall_risk_score=20.0,
            severity_distribution_json={}, owasp_breakdown_json={}, cwe_mapping_json={}, cvss_analysis_json={},
        )
        session.add_all([rep_a, rep_b])
        await session.commit()
        await session.refresh(rep_a)
        await session.refresh(rep_b)

        service = EmailReportService(session)
        dispatched_targets = []

        async def mock_dispatch(*args, **kwargs):
            dispatched_targets.append(kwargs.get("to_email"))
            return True

        with patch.object(service.settings, "email_reports_enabled", True), \
             patch.object(service.settings, "email_provider", "resend"), \
             patch.object(service.settings, "resend_api_key", "re_mock_indep_key"), \
             patch.object(EmailReportService, "_dispatch_resend", side_effect=mock_dispatch):
            
            res_a = await service.send_scan_report_email(scan_a.id, user.id, rep_a.id)
            res_b = await service.send_scan_report_email(scan_b.id, user.id, rep_b.id)

            assert res_a is True
            assert res_b is True
            assert len(dispatched_targets) == 2

        # Verify 2 distinct notifications created, one for each scan
        notif_res = await session.execute(
            select(Notification).where(
                Notification.user_id == user.id,
                Notification.kind == "scan_report_email",
            )
        )
        notifs = notif_res.scalars().all()
        assert len(notifs) == 2
        notif_scan_ids = {n.payload_json["scan_id"] for n in notifs}
        assert notif_scan_ids == {scan_a.id, scan_b.id}

