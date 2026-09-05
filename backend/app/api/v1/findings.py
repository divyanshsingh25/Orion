from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.database.session import get_db
from app.models import User
from app.schemas.common import PaginationParams
from app.schemas.finding import FindingRead
from app.services.finding_service import FindingService


router = APIRouter(prefix="/findings")


@router.get("")
async def list_findings(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    search: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    params = PaginationParams(page=page, page_size=page_size, search=search)
    return await FindingService(db).list_findings(current_user, params, project_id, scan_id, severity)
