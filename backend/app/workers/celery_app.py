from __future__ import annotations

from celery import Celery

from app.core.config import get_settings


settings = get_settings()
celery_app = Celery("orion", broker=settings.celery_broker_url, backend=settings.celery_result_backend)
celery_app.conf.task_routes = {
    "app.workers.tasks.execute_scan_task": {"queue": "scans"},
    "app.workers.tasks.send_scan_report_email_task": {"queue": "emails"},
}

