from __future__ import annotations

import asyncio

from app.database.session import AsyncSessionLocal
from app.services.scan_service import ScanService
from app.workers.celery_app import celery_app


@celery_app.task(name="app.workers.tasks.execute_scan_task")
def execute_scan_task(scan_id: str) -> str:
    async def _run() -> str:
        async with AsyncSessionLocal() as db:
            service = ScanService(db)
            await service.run_scan(scan_id)
            return scan_id

    return asyncio.run(_run())


@celery_app.task(name="app.workers.tasks.send_scan_report_email_task")
def send_scan_report_email_task(scan_id: str, user_id: str, report_id: str | None = None) -> bool:
    from app.services.email_report_service import EmailReportService

    async def _run() -> bool:
        async with AsyncSessionLocal() as db:
            service = EmailReportService(db)
            return await service.send_scan_report_email(scan_id, user_id, report_id)

    return asyncio.run(_run())

