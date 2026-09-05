import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import HTTPException
from sqlalchemy import delete

from app.database.session import AsyncSessionLocal
from app.models import User
from app.schemas.auth import LoginRequest, RegisterRequest
from app.services.auth_service import AuthService


async def run_all_tests():
    print("================================================================")
    print("      RUNNING USERNAME & AUTHENTICATION TEST SUITE              ")
    print("================================================================")

    async with AsyncSessionLocal() as db:
        service = AuthService(db)

        # ---------------------------------------------------------
        # 1. Existing Admin Parity: Login by email and by username
        # ---------------------------------------------------------
        print("\n[TEST 1] Admin login parity (email vs username)...")
        # By email
        res_email = await service.login(LoginRequest(identifier="admin@orion.sec", password="OrionDemo123!"))
        assert res_email.tokens.access_token is not None
        assert res_email.user.username == "admin"
        assert res_email.user.email == "admin@orion.sec"
        print("  [PASS] Admin logged in using email (admin@orion.sec)")

        # By username
        res_uname = await service.login(LoginRequest(identifier="admin", password="OrionDemo123!"))
        assert res_uname.tokens.access_token is not None
        assert res_uname.user.username == "admin"
        print("  [PASS] Admin logged in using username (admin)")

        # Invalid password
        try:
            await service.login(LoginRequest(identifier="admin", password="WrongPassword!123"))
            assert False, "Should have raised 401 for wrong password"
        except HTTPException as exc:
            assert exc.status_code == 401
            print("  [PASS] Invalid password correctly rejected with 401")

        # ---------------------------------------------------------
        # 2. Registration with custom username and uniqueness constraints
        # ---------------------------------------------------------
        print("\n[TEST 2] Registration with username and uniqueness constraints...")
        test_email1 = "auth_test_user1@example.com"
        test_uname1 = "sec_analyst_01"

        # Cleanup any previous test run
        await db.execute(delete(User).where(User.email.in_([test_email1, "auth_test_user2@example.com"])))
        await db.commit()

        # Register user with explicit username
        reg1 = await service.register(
            RegisterRequest(
                email=test_email1,
                username=test_uname1,
                password="TestPassword123!Secure",
                full_name="Security Analyst",
                organization="Security Operations Inc",
            )
        )
        assert reg1["user"].username == test_uname1
        assert reg1["user"].organization == "Security Operations Inc"
        print(f"  [PASS] Registered new user with username: {test_uname1}")

        # Attempt to register duplicate username
        try:
            await service.register(
                RegisterRequest(
                    email="different_email@example.com",
                    username=test_uname1,
                    full_name="Duplicate Tester",
                    organization="Security Operations Inc",
                    password="TestPassword123!Secure",
                )
            )
            assert False, "Should have raised 409 for duplicate username"
        except HTTPException as exc:
            assert exc.status_code == 409
            assert "Username already taken" in exc.detail or "already exists" in exc.detail
            print("  [PASS] Duplicate username rejected with 409")

        # Verify username, full_name, and organization are compulsory
        from pydantic import ValidationError
        try:
            RegisterRequest(email="test_compulsory@example.com", password="TestPassword123!Secure")
            assert False, "Should fail validation when username, full_name, and organization are missing"
        except ValidationError:
            print("  [PASS] Missing compulsory fields correctly rejected by schema validation")

        # Verify password min length of 8 characters
        try:
            RegisterRequest(
                email="short_pw@example.com",
                username="short_pw_user",
                full_name="Short PW",
                organization="Security Operations Inc",
                password="1234567",  # 7 chars
            )
            assert False, "Should fail validation when password is less than 8 characters"
        except ValidationError:
            print("  [PASS] Password with <8 characters correctly rejected by schema validation")

        # Register second user with 8-character password and all compulsory fields
        reg2 = await service.register(
            RegisterRequest(
                email="auth_test_user2@example.com",
                username="sec_analyst_02",
                full_name="Analyst Two",
                organization="Cyber Defense Corp",
                password="pass1234",  # exactly 8 chars
            )
        )
        assert reg2["user"].username == "sec_analyst_02"
        assert reg2["user"].full_name == "Analyst Two"
        assert reg2["user"].organization == "Cyber Defense Corp"
        print(f"  [PASS] Registered second user with 8-char password: {reg2['user'].username}")

        # ---------------------------------------------------------
        # 3. Dual identifier login for newly registered user
        # ---------------------------------------------------------
        print("\n[TEST 3] Login newly registered user via username and email...")
        from app.core.deps import EmailNotVerifiedException
        try:
            await service.login(LoginRequest(identifier=test_uname1, password="TestPassword123!Secure"))
            assert False, "Should have rejected unverified user with EmailNotVerifiedException"
        except EmailNotVerifiedException:
            print("  [PASS] Unverified user login correctly rejected with EmailNotVerifiedException (403)")

        # Verify email for test user
        user_to_verify = await service._get_user_by_email(test_email1)
        assert user_to_verify is not None
        user_to_verify.is_verified = True
        await db.commit()

        # Via username
        login_u = await service.login(LoginRequest(identifier=test_uname1, password="TestPassword123!Secure"))
        assert login_u.user.email == test_email1
        print("  [PASS] Logged in using username")

        # Via email
        login_e = await service.login(LoginRequest(identifier=test_email1, password="TestPassword123!Secure"))
        assert login_e.user.username == test_uname1
        print("  [PASS] Logged in using email")

        # ---------------------------------------------------------
        # 4. Profile retrieval and update
        # ---------------------------------------------------------
        print("\n[TEST 4] Profile retrieval and update...")
        from app.schemas.auth import UpdateProfileRequest
        user_res = await service._get_user_by_email(test_email1)
        assert user_res is not None
        me_data = await service.me(user_res)
        assert me_data.username == test_uname1
        assert me_data.email == test_email1
        print("  [PASS] /auth/me returned correct user profile")

        updated_profile = await service.update_profile(
            user_res,
            UpdateProfileRequest(full_name="Updated Analyst Name", username="sec_analyst_renamed"),
        )
        assert updated_profile.full_name == "Updated Analyst Name"
        assert updated_profile.username == "sec_analyst_renamed"
        print("  [PASS] Profile updated successfully with unique username")

        # Clean up test records
        await db.execute(delete(User).where(User.email.in_([test_email1, "auth_test_user2@example.com"])))
        await db.commit()

    print("\n================================================================")
    print("       ALL USERNAME & AUTHENTICATION TESTS PASSED!              ")
    print("================================================================")


if __name__ == "__main__":
    asyncio.run(run_all_tests())
