from __future__ import annotations

from sqlalchemy import ForeignKey, JSON, Numeric, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import TimestampMixin, UUIDMixin


class AIAnalysis(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "ai_analysis"

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), unique=True, nullable=True)
    simple_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    technical_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    business_impact: Mapped[str] = mapped_column(Text, nullable=False)
    risk_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    owasp_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    cwe_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_steps_json: Mapped[list] = mapped_column(JSON, nullable=False)
    best_practices_json: Mapped[list] = mapped_column(JSON, nullable=False)
    secure_coding_recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    verification_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    code_example: Mapped[str | None] = mapped_column(Text, nullable=True)
    references_json: Mapped[list] = mapped_column(JSON, nullable=False)
    generated_by: Mapped[str] = mapped_column(Text, default="orion-ai", nullable=False)
    verification_verdict: Mapped[str | None] = mapped_column(Text, default="POTENTIAL", nullable=True)
    verification_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_confidence: Mapped[float | None] = mapped_column(Numeric(3, 2), default=0.50, nullable=True)
    context_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    scan = relationship("Scan", back_populates="ai_analyses")
    finding = relationship("Finding", back_populates="ai_analysis")
