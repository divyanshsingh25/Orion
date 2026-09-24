from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class NotificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    title: str
    message: str
    payload_json: dict[str, Any] | None = None
    read_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class NotificationsResponse(BaseModel):
    items: list[NotificationRead]
    unread_count: int
