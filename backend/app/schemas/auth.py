from __future__ import annotations

from datetime import datetime

from pydantic import EmailStr, Field

from app.schemas.common import ORIONSchema


class RegisterRequest(ORIONSchema):
    email: EmailStr
    password: str = Field(min_length=8)
    username: str = Field(min_length=3, max_length=30, pattern=r"^[a-zA-Z0-9_.-]+$")
    full_name: str = Field(min_length=1, max_length=100)
    organization: str = Field(min_length=1, max_length=100)


class UpdateProfileRequest(ORIONSchema):
    full_name: str | None = None
    username: str | None = Field(default=None, min_length=3, max_length=30, pattern=r"^[a-zA-Z0-9_.-]+$")
    organization: str | None = None


class LoginRequest(ORIONSchema):
    identifier: str | None = None
    email: str | None = None
    username: str | None = None
    password: str


class RefreshRequest(ORIONSchema):
    refresh_token: str


class ForgotPasswordRequest(ORIONSchema):
    email: EmailStr


class ResetPasswordRequest(ORIONSchema):
    token: str
    password: str = Field(min_length=8)


class ResendVerificationRequest(ORIONSchema):
    email: EmailStr


class VerifyEmailRequest(ORIONSchema):
    token: str
    email: str | None = None


class TokenPair(ORIONSchema):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserRead(ORIONSchema):
    id: str
    email: EmailStr
    username: str | None = None
    full_name: str | None = None
    organization: str | None = None
    role: str = "user"
    auth_provider: str = "email"
    avatar_url: str | None = None
    is_active: bool
    is_verified: bool
    created_at: datetime


class AuthResponse(ORIONSchema):
    user: UserRead
    tokens: TokenPair
