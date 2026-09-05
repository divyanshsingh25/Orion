from __future__ import annotations

from typing import Any

from app.schemas.common import ORIONSchema
from app.schemas.finding import FindingRead
from app.schemas.scan import LiveModuleRead, TerminalEventRead


class MetricRead(ORIONSchema):
    label: str
    value: int | float
    delta: str
    trend: str
    accent: str


class ChartDatumRead(ORIONSchema):
    name: str
    value: int | float
    color: str


class RiskRead(ORIONSchema):
    title: str
    severity: str


class ReportItemRead(ORIONSchema):
    id: str
    name: str
    type: str
    audience: str
    updated: str
    pages: int
    status: str
    score: int
    scan_id: str


class DashboardResponse(ORIONSchema):
    metrics: list[MetricRead]
    severity: list[ChartDatumRead]
    status: list[ChartDatumRead]
    attackVectors: list[ChartDatumRead]
    cvss: list[ChartDatumRead]
    coverage: list[ChartDatumRead]
    activity: list[dict[str, Any]]
    risks: list[RiskRead]
    assistantMessages: list[dict[str, str]]
    terminalEvents: list[TerminalEventRead]
    liveModules: list[LiveModuleRead]
    reports: list[ReportItemRead]
    vulnerabilities: list[FindingRead]
    scanHistory: list[dict[str, Any]]
    attackSurfaceAssets: list[dict[str, Any]]
    scanSummary: dict[str, Any]
    securityScore: float = 100.0

