from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, JSON, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import TimestampMixin, UUIDMixin


class Finding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "findings"

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False)
    source_module: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    finding_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    http_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    owasp_category: Mapped[str] = mapped_column(String(128), nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(32), nullable=False)
    cwe_name: Mapped[str] = mapped_column(String(255), nullable=False)
    cvss_score: Mapped[float] = mapped_column(Numeric(3, 1), nullable=False)
    cvss_vector: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_rating: Mapped[str] = mapped_column(String(32), nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    best_practices: Mapped[str | None] = mapped_column(Text, nullable=True)
    secure_coding: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_guidance: Mapped[str | None] = mapped_column(Text, nullable=True)
    references_json: Mapped[list | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # --- Finding correlation / lifecycle tracking ---
    correlation_key: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    lifecycle_status: Mapped[str | None] = mapped_column(String(32), default="new", nullable=True)
    first_seen_scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen_scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    scan = relationship("Scan", back_populates="findings")
    project = relationship("Project", back_populates="findings")
    target = relationship("Target", back_populates="findings")
    ai_analysis = relationship("AIAnalysis", back_populates="finding", uselist=False, cascade="all, delete-orphan")
