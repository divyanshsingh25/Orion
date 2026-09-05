from __future__ import annotations

from datetime import datetime

from app.schemas.common import ORIONSchema


class TargetCreate(ORIONSchema):
    url: str
    project_id: str


class TargetRead(ORIONSchema):
    id: str
    project_id: str
    url: str
    scheme: str
    host: str
    port: int | None = None
    status: str
    risk_score: float
    validated_at: datetime | None = None
    created_at: datetime
