from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import TimestampMixin, UUIDMixin


class Scan(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "scans"

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    scan_type: Mapped[str] = mapped_column(String(64), default="full", nullable=False)
    depth: Mapped[str] = mapped_column(String(64), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True, nullable=False)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_module: Mapped[str | None] = mapped_column(String(128), nullable=True)
    current_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    statistics_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    summary_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # --- NEW: real recon data persisted from scan ---
    recon_dns_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    recon_whois_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    recon_ports_json: Mapped[list | None] = mapped_column(JSON, nullable=True)
    recon_services_json: Mapped[list | None] = mapped_column(JSON, nullable=True)
    recon_os_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    endpoints_json: Mapped[list | None] = mapped_column(JSON, nullable=True)
    requests_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    endpoints_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # --- Authentication config for scanning authenticated surfaces ---
    auth_config_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # --- Adaptive scanning and correlation metadata ---
    adaptive_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    correlation_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    project = relationship("Project", back_populates="scans")
    target = relationship("Target", back_populates="scans", foreign_keys=[target_id])
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    ai_analyses = relationship("AIAnalysis", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
