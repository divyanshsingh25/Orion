from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Response, Query
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.database.session import get_db
from app.models import User
from app.schemas.report import ReportRead
from app.services.report_service import ReportService


router = APIRouter(prefix="/reports")


@router.get("", response_model=list[ReportRead])
async def list_reports(project_id: str | None = Query(default=None), scan_id: str | None = Query(default=None), current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await ReportService(db).list_reports(current_user, project_id, scan_id)


@router.post("/generate/{scan_id}", response_model=ReportRead)
async def generate_report(scan_id: str, format: str = Query(default="json"), current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await ReportService(db).generate_report(current_user, scan_id, format)


@router.get("/{report_id}/download")
async def download_report(report_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    service = ReportService(db)
    reports = await service.list_reports(current_user)
    for report in reports:
        if report.id == report_id:
            return FileResponse(report.file_path, filename=Path(report.file_path).name)
    return Response(status_code=404)

@router.delete("/{report_id}", status_code=204)
async def delete_report(report_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await ReportService(db).delete_report(current_user, report_id)
    return Response(status_code=204)
