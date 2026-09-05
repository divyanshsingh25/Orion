from __future__ import annotations

from datetime import datetime
from typing import Any

from app.schemas.common import ORIONSchema


class ReportRead(ORIONSchema):
    id: str
    scan_id: str
    project_id: str
    target_id: str
    report_format: str
    file_path: str
    file_size: int | None = None
    executive_summary: str
    overall_risk_score: float
    severity_distribution_json: dict[str, Any]
    owasp_breakdown_json: dict[str, Any]
    cwe_mapping_json: dict[str, Any]
    cvss_analysis_json: dict[str, Any]
    generated_at: datetime
