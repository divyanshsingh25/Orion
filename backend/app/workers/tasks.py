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
