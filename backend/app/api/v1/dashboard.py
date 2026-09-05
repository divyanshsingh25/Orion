from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.database.session import get_db
from app.models import User
from app.schemas.dashboard import DashboardResponse
from app.services.dashboard_service import DashboardService


router = APIRouter(prefix="/dashboard")


@router.get("/summary", response_model=DashboardResponse)
async def summary(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await DashboardService(db).get_dashboard(current_user)
