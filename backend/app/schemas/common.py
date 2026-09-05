from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ORIONSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class MessageResponse(ORIONSchema):
    message: str
    dev_token: str | None = None
    already_verified: bool = False


class PaginationParams(ORIONSchema):
    page: int = 1
    page_size: int = 20
    search: str | None = None
    sort_by: str | None = None
    sort_order: str = "desc"
