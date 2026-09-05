from __future__ import annotations

from datetime import datetime

from app.schemas.common import ORIONSchema


class ProjectCreate(ORIONSchema):
    name: str
    description: str | None = None


class ProjectUpdate(ORIONSchema):
    name: str | None = None
    description: str | None = None


class ProjectRead(ORIONSchema):
    id: str
    user_id: str
    name: str
    description: str | None = None
    scan_count: int
    target_count: int
    risk_score: float
    created_at: datetime
