from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ORION_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "ORION"
    app_version: str = "1.0.0"
    api_v1_prefix: str = "/api/v1"
    frontend_url: str = Field(
        default="http://localhost:5173",
        validation_alias=AliasChoices("FRONTEND_URL", "ORION_FRONTEND_URL"),
    )
    cors_origins: List[str] = Field(default_factory=lambda: ["http://localhost:5173"])

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
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

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
    scan_max_duration_seconds: float = 600.0
    scan_safe_mode: bool = True

    # LLM Integration
    llm_api_key: str | None = None
    llm_base_url: str | None = None
    llm_model: str = "gpt-4o-mini"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: object) -> List[str]:
        if value is None:
            return ["http://localhost:5173"]
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return list(value)


@lru_cache
def get_settings() -> Settings:
    return Settings()
