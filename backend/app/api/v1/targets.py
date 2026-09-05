from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.database.session import get_db
from app.models import User
from app.schemas.target import TargetCreate, TargetRead
from app.services.target_service import TargetService


router = APIRouter(prefix="/targets")


@router.get("", response_model=list[TargetRead])
async def list_targets(project_id: str | None = Query(default=None), current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await TargetService(db).list_targets(current_user, project_id)


@router.post("", response_model=TargetRead)
async def create_target(payload: TargetCreate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await TargetService(db).create_target(current_user, payload)
