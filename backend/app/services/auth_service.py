from __future__ import annotations

import hashlib
import re
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.deps import EmailNotVerifiedException
from app.core.security import create_token_pair, hash_password, verify_password
from app.models import User
from app.schemas.auth import AuthResponse, LoginRequest, RegisterRequest, TokenPair, UpdateProfileRequest, UserRead
from app.services.notification_service import NotificationService


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.settings = get_settings()
        self.notifications = NotificationService(db)

    async def register(self, payload: RegisterRequest) -> dict:
        email_clean = payload.email.lower().strip()
        result = await self.db.execute(select(User).where(func.lower(User.email) == email_clean))
        if result.scalar_one_or_none() is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

        uname_clean = payload.username.strip()
        if not uname_clean:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username is required")

        full_name_clean = payload.full_name.strip()
        if not full_name_clean:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Full name is required")

        org_clean = payload.organization.strip()
        if not org_clean:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Organization is required")

        uname_check = await self.db.execute(select(User).where(func.lower(User.username) == uname_clean.lower()))
        if uname_check.scalar_one_or_none() is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")
        username = uname_clean

        verification_token = secrets.token_urlsafe(32)
        user = User(
            email=email_clean,
            username=username,
            full_name=full_name_clean,
            organization=org_clean,
            password_hash=hash_password(payload.password),
            role="user",
            auth_provider="email",
            is_active=True,
            is_verified=False,
            verification_token_hash=_hash_token(verification_token),
            verification_token_expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        self.db.add(user)
        try:
            await self.db.flush()
            await self.notifications.send_verification_email(user, verification_token)
            await self.db.commit()
        except IntegrityError:
            await self.db.rollback()
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email or username already exists")

        resp = {"user": self._to_user_read(user), "message": "Account created. Verify your email to complete setup."}
        if not self.settings.smtp_host or not self.settings.smtp_from_email:
            resp["dev_token"] = verification_token
        return resp

    async def login(self, payload: LoginRequest) -> AuthResponse:
        identifier = (payload.identifier or payload.username or payload.email or "").strip().lower()
        if not identifier:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or username is required")

        user = await self._get_user_by_identifier(identifier)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        if not user.password_hash:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Password is not set for this account.",
            )

        if not verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is deactivated")

        if not user.is_verified:
            raise EmailNotVerifiedException()

        access_token, refresh_token, expires_in = create_token_pair(user.id)
        user.current_refresh_token_hash = _hash_token(refresh_token)
        user.current_refresh_token_expires_at = datetime.now(UTC) + timedelta(days=30)
        await self.db.commit()
        return AuthResponse(
            user=self._to_user_read(user),
            tokens=TokenPair(access_token=access_token, refresh_token=refresh_token, expires_in=expires_in),
        )

    async def refresh(self, refresh_token: str) -> TokenPair:
        try:
            from app.core.security import decode_token

            payload = decode_token(refresh_token)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc

        if payload.get("typ") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

        user = await self._get_user_by_id(payload.get("sub", ""))
        if user is None or user.current_refresh_token_hash != _hash_token(refresh_token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been revoked")

        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is deactivated")

        if not user.is_verified:
            raise EmailNotVerifiedException()

        access_token, new_refresh_token, expires_in = create_token_pair(user.id)
        user.current_refresh_token_hash = _hash_token(new_refresh_token)
        user.current_refresh_token_expires_at = datetime.now(UTC) + timedelta(days=30)
        await self.db.commit()
        return TokenPair(access_token=access_token, refresh_token=new_refresh_token, expires_in=expires_in)

    async def verify_email(self, token: str, email: str | None = None) -> dict:
        clean_token = token.strip()
        result = await self.db.execute(select(User).where(User.verification_token_hash == _hash_token(clean_token)))
        user = result.scalar_one_or_none()

        if user is None:
            if email:
                existing = await self._get_user_by_email(email.lower().strip())
                if existing and existing.is_verified:
                    return {
                        "message": "This account is already verified! You can proceed to log in.",
                        "already_verified": True,
                        "is_verified": True,
                    }
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")

        if not user.verification_token_expires_at or user.verification_token_expires_at < datetime.now(UTC):
            if user.is_verified:
                return {
                    "message": "This account is already verified! You can proceed to log in.",
                    "already_verified": True,
                    "is_verified": True,
                }
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")

        user.is_verified = True
        user.email_verified_at = datetime.now(UTC)
        user.verification_token_hash = None
        user.verification_token_expires_at = None
        await self.db.commit()
        return {"message": "Email verified successfully", "is_verified": True, "already_verified": False}

    async def resend_verification(self, email: str) -> dict:
        email_clean = email.lower().strip()
        user = await self._get_user_by_email(email_clean)
        if user is None:
            return {"message": "If the account exists and requires verification, a verification email has been sent."}

        if user.is_verified:
            return {
                "message": "This account is already verified! You can log in directly.",
                "already_verified": True,
            }

        verification_token = secrets.token_urlsafe(32)
        user.verification_token_hash = _hash_token(verification_token)
        user.verification_token_expires_at = datetime.now(UTC) + timedelta(days=1)
        await self.notifications.send_verification_email(user, verification_token)
        await self.db.commit()

        resp = {"message": "Verification email sent successfully."}
        if not self.settings.smtp_host or not self.settings.smtp_from_email:
            resp["dev_token"] = verification_token
            resp["message"] = "Verification code generated! Click 'Verify Account' below to activate."
        return resp

    async def forgot_password(self, email: str) -> dict:
        user = await self._get_user_by_email(email.lower())
        if user is None:
            return {"message": "If the account exists, a reset email has been sent"}

        token = secrets.token_urlsafe(32)
        user.reset_token_hash = _hash_token(token)
        user.reset_token_expires_at = datetime.now(UTC) + timedelta(hours=2)
        await self.notifications.send_password_reset_email(user, token)
        await self.db.commit()
        return {"message": "Password reset instructions sent"}

    async def reset_password(self, token: str, password: str) -> dict:
        result = await self.db.execute(select(User).where(User.reset_token_hash == _hash_token(token)))
        user = result.scalar_one_or_none()
        if user is None or not user.reset_token_expires_at or user.reset_token_expires_at < datetime.now(UTC):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

        user.password_hash = hash_password(password)
        user.reset_token_hash = None
        user.reset_token_expires_at = None
        user.current_refresh_token_hash = None
        user.current_refresh_token_expires_at = None
        await self.db.commit()
        return {"message": "Password reset successfully"}

    async def me(self, user: User) -> UserRead:
        return self._to_user_read(user)

    async def update_profile(self, user: User, payload: UpdateProfileRequest) -> UserRead:
        if payload.username and payload.username.strip():
            new_uname = payload.username.strip()
            if new_uname.lower() != (user.username or "").lower():
                uname_check = await self.db.execute(select(User).where(func.lower(User.username) == new_uname.lower()))
                if uname_check.scalar_one_or_none() is not None:
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")
                user.username = new_uname
        if payload.full_name is not None:
            user.full_name = payload.full_name.strip() or None
        if payload.organization is not None:
            user.organization = payload.organization.strip() or None

        await self.db.commit()
        await self.db.refresh(user)
        return self._to_user_read(user)

    async def _generate_unique_username(self, base_name: str) -> str:
        """Generate a collision-safe username based on an email prefix or name."""
        cleaned = re.sub(r"[^a-z0-9_.-]", "", base_name.lower().strip())
        if not cleaned or len(cleaned) < 3:
            cleaned = f"user_{cleaned}" if cleaned else "user"

        candidate = cleaned[:30]
        counter = 2
        while True:
            res = await self.db.execute(select(User).where(func.lower(User.username) == candidate.lower()))
            if res.scalar_one_or_none() is None:
                return candidate
            suffix = str(counter)
            candidate = f"{cleaned[:30-len(suffix)]}{suffix}"
            counter += 1

    async def _get_user_by_identifier(self, identifier: str) -> User | None:
        ident = identifier.strip().lower()
        result = await self.db.execute(
            select(User).where(or_(func.lower(User.email) == ident, func.lower(User.username) == ident))
        )
        return result.scalar_one_or_none()

    async def _get_user_by_email(self, email: str) -> User | None:
        result = await self.db.execute(select(User).where(func.lower(User.email) == email.lower().strip()))
        return result.scalar_one_or_none()

    async def _get_user_by_id(self, user_id: str) -> User | None:
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    def _to_user_read(self, user: User) -> UserRead:
        return UserRead(
            id=user.id,
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            organization=getattr(user, "organization", None),
            role=getattr(user, "role", "user"),
            auth_provider=user.auth_provider or "email",
            avatar_url=user.avatar_url,
            is_active=user.is_active,
            is_verified=user.is_verified,
            created_at=user.created_at,
        )
