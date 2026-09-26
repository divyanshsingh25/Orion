"""
Automated tests for Resend HTTPS API email delivery in ORION.
Verifies successful send, failure handling, missing keys, OTP flows, report email flows,
and credential/token redaction.
"""
from __future__ import annotations

import base64
import json
import logging
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from sqlalchemy import select

from app.core.config import Settings
from app.database.session import AsyncSessionLocal, async_engine
from app.models import Notification, Project, Report, Scan, Target, User
from app.schemas.auth import RegisterRequest
from app.services.auth_service import AuthService
from app.services.email_report_service import EmailReportService
from app.services.email_transport import sanitize_error_message, send_email_via_resend
from app.services.notification_service import NotificationService


@pytest.fixture(autouse=True)
async def cleanup_engine():
    await async_engine.dispose()
    yield
    await async_engine.dispose()


@pytest.fixture
def resend_settings() -> Settings:
    settings = Settings(_env_file=None)
    settings.email_provider = "resend"
    settings.resend_api_key = "re_mock_test_key_1234567890"
    settings.email_from = "onboarding@resend.dev"
    settings.smtp_from_name = "ORION Security Test"
    settings.email_reports_enabled = True
    return settings


@pytest.mark.asyncio
async def test_resend_successful_email(resend_settings: Settings):
    """Verify that email dispatches successfully via Resend HTTPS API with correct headers and payload."""
    mock_response = httpx.Response(
        status_code=200,
        content=json.dumps({"id": "msg_mock_success_id_999"}).encode("utf-8"),
        request=httpx.Request("POST", "https://api.resend.com/emails"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        success = await send_email_via_resend(
            settings=resend_settings,
            to_email="auditor@example.com",
            subject="Security Alert",
            text_body="Vulnerability detected.",
            html_body="<p>Vulnerability detected.</p>",
        )

        assert success is True
        assert mock_post.called
        call_kwargs = mock_post.call_args.kwargs
        headers = call_kwargs.get("headers", {})
        payload = call_kwargs.get("json", {})

        assert headers.get("Authorization") == f"Bearer {resend_settings.resend_api_key}"
        assert headers.get("Content-Type") == "application/json"
        assert payload.get("to") == ["auditor@example.com"]
        assert payload.get("subject") == "Security Alert"
        assert payload.get("text") == "Vulnerability detected."
        assert payload.get("html") == "<p>Vulnerability detected.</p>"
        assert "ORION Security Test <onboarding@resend.dev>" in payload.get("from")


@pytest.mark.asyncio
async def test_resend_api_failure_handled_gracefully(resend_settings: Settings, caplog):
    """Verify that Resend API non-200 responses return False and log error without crashing."""
    mock_response = httpx.Response(
        status_code=422,
        content=json.dumps({"name": "validation_error", "message": "Domain is not verified"}).encode("utf-8"),
        request=httpx.Request("POST", "https://api.resend.com/emails"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        with caplog.at_level(logging.ERROR):
            success = await send_email_via_resend(
                settings=resend_settings,
                to_email="auditor@example.com",
                subject="Test Failure",
                text_body="Test body",
            )

        assert success is False
        assert "Domain is not verified" in caplog.text


@pytest.mark.asyncio
async def test_resend_missing_api_key(resend_settings: Settings, caplog):
    """Verify that missing API key returns False without crashing or making network calls."""
    resend_settings.resend_api_key = None

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        with caplog.at_level(logging.ERROR):
            success = await send_email_via_resend(
                settings=resend_settings,
                to_email="auditor@example.com",
                subject="No Key",
                text_body="No key body",
            )

        assert success is False
        assert not mock_post.called
        assert "ORION_RESEND_API_KEY is missing" in caplog.text


@pytest.mark.asyncio
async def test_resend_otp_verification_email_flow(resend_settings: Settings):
    """Verify that user registration / verification OTP dispatches through Resend."""
    mock_user = MagicMock()
    mock_user.email = "newuser@example.com"
    mock_user.username = "newuser"
    mock_user.full_name = "New User"

    mock_response = httpx.Response(
        status_code=200,
        content=json.dumps({"id": "otp_email_id_123"}).encode("utf-8"),
        request=httpx.Request("POST", "https://api.resend.com/emails"),
    )

    mock_session = AsyncMock()
    service = NotificationService(mock_session)
    service.settings = resend_settings

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        await service.send_verification_email(mock_user, "849201")

        assert mock_post.called
        payload = mock_post.call_args.kwargs.get("json", {})
        assert payload.get("to") == ["newuser@example.com"]
        assert "849201" in payload.get("subject")
        assert "849201" in payload.get("text")
        assert "849201" in payload.get("html")


@pytest.mark.asyncio
async def test_resend_report_email_flow_with_attachment(resend_settings: Settings, tmp_path):
    """Verify that scan security report email dispatches with base64 PDF attachment via Resend."""
    async with AsyncSessionLocal() as session:
        unique = uuid.uuid4().hex[:8]
        user = User(
            email=f"report_test_{unique}@example.com",
            username=f"rep_{unique}",
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        proj = Project(name=f"ReportProject {unique}", user_id=user.id)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)

        target = Target(project_id=proj.id, scheme="https", host="audit.example.com", url="https://audit.example.com")
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

        # Create dummy PDF report artifact
        pdf_file = tmp_path / "test_report.pdf"
        pdf_file.write_bytes(b"%PDF-1.4 mock binary pdf content for Orion resend test")

        report = Report(
            scan_id=scan.id,
            project_id=proj.id,
            target_id=target.id,
            report_format="pdf",
            file_path=str(pdf_file),
            file_size=pdf_file.stat().st_size,
            executive_summary="Security assessment summary for Resend test.",
            overall_risk_score=45.0,
            severity_distribution_json={"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
            owasp_breakdown_json={},
            cwe_mapping_json={},
            cvss_analysis_json={"critical": 0, "high": 1, "medium": 1, "low": 0},
        )
        session.add(report)
        await session.commit()
        await session.refresh(report)

        service = EmailReportService(session)
        service.settings = resend_settings

        mock_response = httpx.Response(
            status_code=200,
            content=json.dumps({"id": "report_msg_456"}).encode("utf-8"),
            request=httpx.Request("POST", "https://api.resend.com/emails"),
        )

        with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            success = await service.send_scan_report_email(scan.id, user.id)

            assert success is True
            assert mock_post.called
            payload = mock_post.call_args.kwargs.get("json", {})
            assert payload.get("to") == [user.email]
            assert "Security Assessment Report" in payload.get("subject")
            assert "attachments" in payload
            attachments = payload.get("attachments", [])
            assert len(attachments) == 1
            assert attachments[0]["filename"].endswith(".pdf")
            # Verify base64 content can be decoded back
            decoded = base64.b64decode(attachments[0]["content"])
            assert len(decoded) > 0

        # Verify audit notification in database
        notif_res = await session.execute(
            select(Notification).where(
                Notification.user_id == user.id,
                Notification.kind == "scan_report_email",
            )
        )
        notif = notif_res.scalar_one_or_none()
        assert notif is not None
        assert notif.payload_json["delivered"] is True
        assert notif.payload_json["to_email"] == user.email


def test_secret_redaction_utility():
    """Verify that sanitize_error_message completely removes API keys, Bearer headers, and secrets."""
    secret_key = "re_1234567890abcdefghijklmnopqrst"
    secret_pwd = "my_super_secret_password"
    otp_code = "987654"

    raw_message = (
        f"Failed request Authorization: Bearer {secret_key} with key {secret_key} "
        f"and password {secret_pwd} and otp {otp_code}"
    )

    clean_message = sanitize_error_message(raw_message, [secret_key, secret_pwd, otp_code])

    assert secret_key not in clean_message
    assert secret_pwd not in clean_message
    assert otp_code not in clean_message
    assert "Bearer [REDACTED]" in clean_message
    assert "re_[REDACTED]" in clean_message


@pytest.mark.asyncio
async def test_production_registration_never_exposes_otp():
    """Verify that in production environments, dev_token is NEVER returned in the registration API response."""
    async with AsyncSessionLocal() as session:
        unique = uuid.uuid4().hex[:8]
        service = AuthService(session)
        service.settings.environment = "production"
        service.settings.resend_api_key = "re_prod_test_key_123"
        service.settings.email_provider = "resend"

        payload = RegisterRequest(
            email=f"prod_user_{unique}@example.com",
            username=f"prod_user_{unique}",
            password="StrongPassword123!",
            full_name="Production Test User",
            organization="ACME Corp",
        )

        with patch("app.services.email_transport.httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = httpx.Response(
                status_code=200,
                content=json.dumps({"id": "otp_prod_msg_123"}).encode("utf-8"),
                request=httpx.Request("POST", "https://api.resend.com/emails"),
            )
            response = await service.register(payload)

        # In production, dev_token must strictly NEVER be exposed
        assert "dev_token" not in response
        assert "user" in response
        assert "message" in response
        assert "Account created" in response["message"]

        # Test resend-verification also never exposes dev_token in production
        resend_resp = await service.resend_verification(payload.email)
        assert resend_resp.get("dev_token") is None


@pytest.mark.asyncio
async def test_resend_otp_dispatch_called_during_registration():
    """Verify that Resend HTTPS API is actually invoked with the 6-digit OTP when a user registers."""
    async with AsyncSessionLocal() as session:
        unique = uuid.uuid4().hex[:8]
        service = AuthService(session)
        service.settings.environment = "production"
        service.settings.email_provider = "resend"
        service.settings.resend_api_key = "re_live_test_api_key_abc123"
        service.settings.email_from = "onboarding@resend.dev"

        # Also update the notifications service settings on AuthService
        service.notifications.settings = service.settings

        payload = RegisterRequest(
            email=f"dispatch_test_{unique}@example.com",
            username=f"disp_{unique}",
            password="SecurePassword456!",
            full_name="Dispatch Test User",
            organization="Cyber Security",
        )

        with patch("app.services.email_transport.httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = httpx.Response(
                status_code=200,
                content=json.dumps({"id": "msg_otp_dispatched_789"}).encode("utf-8"),
                request=httpx.Request("POST", "https://api.resend.com/emails"),
            )

            response = await service.register(payload)

            assert mock_post.called
            call_kwargs = mock_post.call_args.kwargs
            json_body = call_kwargs.get("json", {})
            headers = call_kwargs.get("headers", {})

            # Verify recipient
            assert json_body.get("to") == [payload.email]
            # Verify sender
            assert "onboarding@resend.dev" in json_body.get("from")
            # Verify authorization header
            assert headers.get("Authorization") == f"Bearer {service.settings.resend_api_key}"
            # Verify subject and OTP text
            assert "Your ORION Verification OTP:" in json_body.get("subject")
            assert len(json_body.get("text")) > 0
            assert len(json_body.get("html")) > 0

