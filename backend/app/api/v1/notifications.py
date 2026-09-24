from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.database.session import get_db
from app.models import User
from app.schemas.notification import NotificationRead, NotificationsResponse
from app.services.notification_service import NotificationService

router = APIRouter(prefix="/notifications")


@router.get("", response_model=NotificationsResponse)
async def list_notifications(
    limit: int = Query(default=30, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = NotificationService(db)
    items = await service.list_notifications(current_user, limit=limit)
    unread_count = await service.get_unread_count(current_user)
    return NotificationsResponse(
        items=[NotificationRead.model_validate(item) for item in items],
        unread_count=unread_count,
    )


@router.post("/read-all", status_code=status.HTTP_200_OK)
async def mark_all_notifications_read(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = NotificationService(db)
    updated_count = await service.mark_all_as_read(current_user)
    return {"updated": updated_count, "message": "All notifications marked as read"}


@router.post("/{notification_id}/read", response_model=NotificationRead | None)
async def mark_notification_read(
    notification_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = NotificationService(db)
    notification = await service.mark_as_read(current_user, notification_id)
    return NotificationRead.model_validate(notification) if notification else None
