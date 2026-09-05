import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from app.core.deps import EmailNotVerifiedException
from app.core.security import create_token_pair
from app.database.session import AsyncSessionLocal
from app.main import app
from app.models import Notification, User
from app.schemas.auth import LoginRequest, RegisterRequest
from app.services.auth_service import AuthService


async def run_mandatory_verification_tests():
    print("================================================================")
    print("     MANDATORY EMAIL VERIFICATION & ZERO ACCESS TEST SUITE      ")
    print("================================================================")

    test_email = "unverified_test_user@example.com"
    test_uname = "unverified_tester"
    test_pwd = "StrongPassword123!"

    # Clean up test user if exists
    async with AsyncSessionLocal() as db:
        await db.execute(delete(User).where(User.email == test_email))
        await db.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:

        # -------------------------------------------------------------
        # STEP 1: Registration creates unverified account with zero session tokens
        # -------------------------------------------------------------
        print("\n[STEP 1] Testing public registration...")
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": test_email,
                "username": test_uname,
                "full_name": "Unverified Tester",
                "organization": "Security Operations Inc",
                "password": test_pwd,
                "role": "admin",  # Attempt to inject admin role
                "is_verified": True,  # Attempt to inject is_verified
            },
        )
        assert reg_resp.status_code == 200, f"Registration failed: {reg_resp.text}"
        reg_data = reg_resp.json()
        assert "tokens" not in reg_data, "Registration MUST NOT issue tokens"
        assert reg_data["user"]["is_verified"] is False, "User must NOT be verified on registration"
        assert reg_data["user"]["role"] == "user", "Role MUST NOT be admin from public registration"
        print("  [PASS] Public registration creates account with is_verified=False and role='user'")
        print("  [PASS] No access/refresh tokens issued upon registration")

        # Verify database state directly
        async with AsyncSessionLocal() as db:
            db_user = (await db.execute(select(User).where(User.email == test_email))).scalar_one()
            assert db_user.is_verified is False
            assert db_user.role == "user"
            assert db_user.verification_token_hash is not None
            # Retrieve verification token from notification to simulate email link
            notif = (
                await db.execute(
                    select(Notification)
                    .where(Notification.user_id == db_user.id, Notification.kind == "email_verification")
                )
            ).scalar_one_or_none()
            assert notif is not None
            raw_token = notif.payload_json.get("token")
            assert raw_token is not None
            user_id = db_user.id

        # -------------------------------------------------------------
        # STEP 2: Login rejected with 403 EMAIL_NOT_VERIFIED
        # -------------------------------------------------------------
        print("\n[STEP 2] Testing login rejection for unverified user...")
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"identifier": test_email, "password": test_pwd},
        )
        assert login_resp.status_code == 403, f"Expected 403, got {login_resp.status_code}: {login_resp.text}"
        login_data = login_resp.json()
        assert login_data.get("code") == "EMAIL_NOT_VERIFIED", f"Expected code EMAIL_NOT_VERIFIED, got {login_data}"
        assert login_data.get("detail") == "Email verification required"
        assert "tokens" not in login_data
        print(f"  [PASS] Login rejected with HTTP 403 and {login_data}")

        # Also test login by username
        login_uname_resp = await client.post(
            "/api/v1/auth/login",
            json={"identifier": test_uname, "password": test_pwd},
        )
        assert login_uname_resp.status_code == 403
        assert login_uname_resp.json().get("code") == "EMAIL_NOT_VERIFIED"
        print("  [PASS] Username login also rejected with HTTP 403 EMAIL_NOT_VERIFIED")

        # -------------------------------------------------------------
        # STEP 3: Protected API Rejection across EVERY endpoint category
        # Even with a forged or stale JWT access token
        # -------------------------------------------------------------
        print("\n[STEP 3] Testing backend enforcement across ALL protected API categories...")
        # Mint an access token for this unverified user to simulate stale token or client-side tampering
        stale_access_token, _, _ = create_token_pair(user_id)
        auth_headers = {"Authorization": f"Bearer {stale_access_token}"}

        endpoints_to_test = [
            ("GET", "/api/v1/auth/me", None),
            ("PUT", "/api/v1/auth/me", {"full_name": "Hacked Name"}),
            ("GET", "/api/v1/dashboard/summary", None),
            ("GET", "/api/v1/projects", None),
            ("POST", "/api/v1/projects", {"name": "Unauthorized Project"}),
            ("GET", "/api/v1/targets", None),
            ("POST", "/api/v1/targets", {"project_id": "dummy", "target_url": "https://example.com"}),
            ("GET", "/api/v1/scans", None),
            ("POST", "/api/v1/scans", {"project_id": "dummy", "target_id": "dummy", "scan_type": "quick"}),
            ("GET", "/api/v1/scans/active", None),
            ("GET", "/api/v1/scans/dummy-scan-id", None),
            ("POST", "/api/v1/scans/dummy-scan-id/cancel", None),
            ("GET", "/api/v1/findings", None),
            ("GET", "/api/v1/reports", None),
            ("POST", "/api/v1/reports/generate/dummy-scan-id", None),
            ("GET", "/api/v1/reports/dummy-report-id/download", None),
            ("DELETE", "/api/v1/reports/dummy-report-id", None),
            ("POST", "/api/v1/chat", {"messages": [{"role": "user", "content": "hello"}]}),
        ]

        for method, endpoint, payload in endpoints_to_test:
            if method == "GET":
                resp = await client.get(endpoint, headers=auth_headers)
            elif method == "POST":
                resp = await client.post(endpoint, json=payload, headers=auth_headers)
            elif method == "PUT":
                resp = await client.put(endpoint, json=payload, headers=auth_headers)
            elif method == "DELETE":
                resp = await client.delete(endpoint, headers=auth_headers)
            else:
                raise ValueError(f"Unknown method {method}")

            assert resp.status_code == 403, (
                f"Security breach! Endpoint {method} {endpoint} allowed access (status {resp.status_code}): {resp.text}"
            )
            body = resp.json()
            assert body.get("code") == "EMAIL_NOT_VERIFIED", (
                f"Endpoint {method} {endpoint} did not return EMAIL_NOT_VERIFIED code: {body}"
            )
            print(f"  [PASS] {method:<6} {endpoint:<36} -> 403 {body['code']}")

        # -------------------------------------------------------------
        # STEP 4: Email Verification Token Single-Use & Expiry
        # -------------------------------------------------------------
        print("\n[STEP 4] Testing email verification token processing...")

        # Invalid token rejection
        bad_token_resp = await client.post("/api/v1/auth/verify-email", json={"token": "completely-invalid-token"})
        assert bad_token_resp.status_code == 400
        print("  [PASS] Invalid token rejected with HTTP 400")

        # Valid token verification (via POST)
        verify_resp = await client.post("/api/v1/auth/verify-email", json={"token": raw_token})
        assert verify_resp.status_code == 200, f"Verification failed: {verify_resp.text}"
        print(f"  [PASS] Token verification succeeded: {verify_resp.json()}")

        # Re-use of same token must be rejected (single-use enforcement)
        reuse_resp = await client.post("/api/v1/auth/verify-email", json={"token": raw_token})
        assert reuse_resp.status_code == 400
        print("  [PASS] Single-use enforced: reusing same verification token rejected with HTTP 400")

        # Verify DB reflects is_verified = True
        async with AsyncSessionLocal() as db:
            db_user = (await db.execute(select(User).where(User.email == test_email))).scalar_one()
            assert db_user.is_verified is True
            assert db_user.email_verified_at is not None
            assert db_user.verification_token_hash is None
        print("  [PASS] Database state updated: is_verified=True, token hash cleared")

        # -------------------------------------------------------------
        # STEP 5: Post-Verification Login & Protected Access Restored
        # -------------------------------------------------------------
        print("\n[STEP 5] Testing login and protected API access after verification...")
        login_after = await client.post(
            "/api/v1/auth/login",
            json={"identifier": test_email, "password": test_pwd},
        )
        assert login_after.status_code == 200, f"Login failed after verification: {login_after.text}"
        after_data = login_after.json()
        assert "tokens" in after_data
        valid_access_token = after_data["tokens"]["access_token"]
        valid_headers = {"Authorization": f"Bearer {valid_access_token}"}

        # Check me
        me_resp = await client.get("/api/v1/auth/me", headers=valid_headers)
        assert me_resp.status_code == 200
        me_data = me_resp.json()
        assert me_data["is_verified"] is True
        assert me_data["role"] == "user"
        print("  [PASS] /auth/me returns is_verified=True and role='user'")

        # Check dashboard summary
        dash_resp = await client.get("/api/v1/dashboard/summary", headers=valid_headers)
        assert dash_resp.status_code == 200
        print("  [PASS] /dashboard/summary returns 200 OK")

        # Check projects
        proj_resp = await client.get("/api/v1/projects", headers=valid_headers)
        assert proj_resp.status_code == 200
        print("  [PASS] /projects returns 200 OK")

        # Check targets
        target_resp = await client.get("/api/v1/targets", headers=valid_headers)
        assert target_resp.status_code == 200
        print("  [PASS] /targets returns 200 OK")

        # Check scans
        scans_resp = await client.get("/api/v1/scans", headers=valid_headers)
        assert scans_resp.status_code == 200
        print("  [PASS] /scans returns 200 OK")

        # Check findings
        find_resp = await client.get("/api/v1/findings", headers=valid_headers)
        assert find_resp.status_code == 200
        print("  [PASS] /findings returns 200 OK")

        # Check reports
        rep_resp = await client.get("/api/v1/reports", headers=valid_headers)
        assert rep_resp.status_code == 200
        print("  [PASS] /reports returns 200 OK")

        # -------------------------------------------------------------
        # STEP 6: Resend Verification for Unverified Accounts
        # -------------------------------------------------------------
        print("\n[STEP 6] Testing resend verification endpoint...")
        # Create a second unverified user
        test_email2 = "unverified2@example.com"
        async with AsyncSessionLocal() as db:
            await db.execute(delete(User).where(User.email == test_email2))
            await db.commit()

        await client.post(
            "/api/v1/auth/register",
            json={
                "email": test_email2,
                "username": "unverified2",
                "full_name": "Unverified Two",
                "organization": "Security Operations Inc",
                "password": test_pwd,
            },
        )

        resend_resp = await client.post("/api/v1/auth/resend-verification", json={"email": test_email2})
        assert resend_resp.status_code == 200
        print(f"  [PASS] Resend verification succeeded: {resend_resp.json()['message']}")

        # Verify GET endpoint /auth/verify-email?token=...
        async with AsyncSessionLocal() as db:
            u2 = (await db.execute(select(User).where(User.email == test_email2))).scalar_one()
            notif2 = (
                await db.execute(
                    select(Notification)
                    .where(Notification.user_id == u2.id, Notification.kind == "email_verification")
                    .order_by(Notification.created_at.desc())
                )
            ).scalars().first()
            raw_token2 = notif2.payload_json.get("token")

        get_verify_resp = await client.get(f"/api/v1/auth/verify-email?token={raw_token2}")
        assert get_verify_resp.status_code == 200
        print("  [PASS] GET /auth/verify-email?token=... verification succeeded")

        # Cleanup test users
        async with AsyncSessionLocal() as db:
            await db.execute(delete(User).where(User.email.in_([test_email, test_email2])))
            await db.commit()

    print("\n================================================================")
    print("      ALL MANDATORY EMAIL VERIFICATION TESTS PASSED!            ")
    print("================================================================")


if __name__ == "__main__":
    asyncio.run(run_mandatory_verification_tests())
