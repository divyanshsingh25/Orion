from __future__ import annotations

from decimal import Decimal
from datetime import datetime
from typing import Any

from app.schemas.common import ORIONSchema


class FindingRead(ORIONSchema):
    id: str
    scan_id: str
    project_id: str
    target_id: str
    source_module: str
    finding_type: str
    title: str
    description: str
    evidence: str | None = None
    affected_url: str | None = None
    affected_parameter: str | None = None
    http_request: str | None = None
    http_response: str | None = None
    owasp_category: str
    cwe_id: str
    cwe_name: str
    cvss_score: Decimal
    cvss_vector: str
    severity: str
    confidence: str
    risk_rating: str
    remediation: str
    best_practices: str | None = None
    secure_coding: str | None = None
    verification_guidance: str | None = None
    references_json: list[Any] | None = None
    status: str
    metadata_json: dict[str, Any] | None = None
    created_at: datetime
