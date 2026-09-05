from __future__ import annotations

from datetime import datetime
from typing import Any

from app.schemas.common import ORIONSchema


class ScanCreateRequest(ORIONSchema):
    target_id: str
    scan_type: str = "full"
    depth: str = "medium"
    auth_config: dict | None = None


class ScanProgressRead(ORIONSchema):
    id: str
    status: str
    progress_percent: int
    current_module: str | None = None
    current_url: str | None = None
    total_findings: int


class LiveModuleRead(ORIONSchema):
    name: str
    status: str
    progress: int
    findings: int


class TerminalEventRead(ORIONSchema):
    time: str
    level: str
    message: str


class ScanRead(ORIONSchema):
    id: str
    project_id: str
    target_id: str
    user_id: str
    scan_type: str
    depth: str
    status: str
    progress_percent: int
    current_module: str | None = None
    current_url: str | None = None
    target_url: str | None = None
    total_findings: int
    requests_count: int = 0
    endpoints_count: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    error_message: str | None = None
    statistics_json: dict[str, Any] | None = None
    summary_json: dict[str, Any] | None = None
    auth_config_json: dict | None = None
    adaptive_json: dict | None = None
    correlation_json: dict | None = None
    live_events: list[TerminalEventRead] = []
    live_modules: list[LiveModuleRead] = []
    eta_seconds: int = 0
    report_id: str | None = None
