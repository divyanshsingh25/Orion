from __future__ import annotations

import json
from functools import lru_cache
from typing import List

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ORION_",
        env_file=(".env", "backend/.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "ORION"
    app_version: str = "1.0.0"
    api_v1_prefix: str = "/api/v1"
    frontend_url: str = Field(
        default="https://orion-one-alpha.vercel.app",
        validation_alias=AliasChoices("FRONTEND_URL", "ORION_FRONTEND_URL"),
    )
    cors_origins: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "https://orion-one-alpha.vercel.app",
        ],
        validation_alias=AliasChoices("CORS_ORIGINS", "ORION_CORS_ORIGINS"),
    )

    database_url: str = Field(
        default="postgresql+asyncpg://postgres:change_me@localhost:5432/orion",
        validation_alias=AliasChoices("DATABASE_URL", "ORION_DATABASE_URL"),
    )
    test_database_url: str = Field(
        default="sqlite+aiosqlite:///./orion-test.db",
        validation_alias=AliasChoices("TEST_DATABASE_URL", "ORION_TEST_DATABASE_URL"),
    )
    db_pool_size: int = Field(default=10, validation_alias=AliasChoices("DB_POOL_SIZE", "ORION_DB_POOL_SIZE"))
    db_max_overflow: int = Field(default=20, validation_alias=AliasChoices("DB_MAX_OVERFLOW", "ORION_DB_MAX_OVERFLOW"))
    db_pool_timeout: int = Field(default=30, validation_alias=AliasChoices("DB_POOL_TIMEOUT", "ORION_DB_POOL_TIMEOUT"))
    db_pool_recycle: int = Field(default=1800, validation_alias=AliasChoices("DB_POOL_RECYCLE", "ORION_DB_POOL_RECYCLE"))
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        validation_alias=AliasChoices("REDIS_URL", "REDIS_PRIVATE_URL", "REDISURL", "ORION_REDIS_URL"),
    )
    celery_broker_url: str = Field(
        default="redis://localhost:6379/1",
        validation_alias=AliasChoices("CELERY_BROKER_URL", "REDIS_URL", "REDIS_PRIVATE_URL", "ORION_CELERY_BROKER_URL"),
    )
    celery_result_backend: str = Field(
        default="redis://localhost:6379/2",
        validation_alias=AliasChoices("CELERY_RESULT_BACKEND", "REDIS_URL", "REDIS_PRIVATE_URL", "ORION_CELERY_RESULT_BACKEND"),
    )
    use_celery: bool = Field(
        default=False,
        validation_alias=AliasChoices("USE_CELERY", "ORION_USE_CELERY"),
    )

    secret_key: str = Field(
        default="change-me-in-production",
        validation_alias=AliasChoices("SECRET_KEY", "ORION_SECRET_KEY"),
    )
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 30
    password_min_length: int = 12

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None

    storage_dir: str = "storage"
    report_dir: str = "storage/reports"
    log_dir: str = "storage/logs"
    enable_auto_schema: bool = True
    allow_private_targets: bool = False
    scan_timeout_seconds: int = 300
    scan_connect_timeout_seconds: int = 15
    scan_rate_limit_rps: float = 4.0
    scan_max_rps: float = 10.0
    scan_max_concurrency: int = 5
    scan_max_duration_seconds: float = 900.0
    scan_safe_mode: bool = True

    # LLM Integration
    llm_api_key: str | None = None
    llm_base_url: str | None = None
    llm_model: str = "gpt-4o-mini"

    @field_validator("database_url", mode="before")
    @classmethod
    def normalize_database_url(cls, value: object) -> str:
        if not value:
            return "postgresql+asyncpg://postgres:change_me@localhost:5432/orion"
        url = str(value).strip()
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: object) -> List[str]:
        default_origins = [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "https://orion-one-alpha.vercel.app",
        ]
        if value is None or value == "":
            return default_origins

        raw_items: list[str] = []
        if isinstance(value, str):
            val_str = value.strip()
            if not val_str:
                return default_origins
            if val_str.startswith("[") and val_str.endswith("]"):
                try:
                    parsed = json.loads(val_str)
                    if isinstance(parsed, list):
                        raw_items = [str(x) for x in parsed]
                    else:
                        raw_items = [str(parsed)]
                except Exception:
                    val_str = val_str[1:-1]
                    raw_items = val_str.split(",")
            else:
                raw_items = val_str.split(",")
        elif isinstance(value, (list, tuple, set)):
            raw_items = [str(x) for x in value]
        else:
            raw_items = [str(value)]

        cleaned: list[str] = []
        for item in raw_items:
            s = item.strip().strip("'\"").rstrip("/")
            if s and s not in cleaned:
                cleaned.append(s)

        # Always ensure standard localhost and production vercel are included
        for fallback in default_origins:
            if fallback not in cleaned:
                cleaned.append(fallback)

        return cleaned


@lru_cache
def get_settings() -> Settings:
    return Settings()
