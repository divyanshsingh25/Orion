from __future__ import annotations

from typing import Any

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, User
from app.schemas.common import PaginationParams
from app.schemas.finding import FindingRead


class FindingService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def list_findings(self, user: User, params: PaginationParams, project_id: str | None = None, scan_id: str | None = None, severity: str | None = None) -> dict[str, Any]:
        user_project_subquery = select(Finding.project_id).join(Finding.project).where(Finding.project.has(user_id=user.id))
        
        # Calculate scope-wide severity counts (before severity filter is applied)
        count_q = select(func.lower(Finding.severity), func.count()).where(Finding.project_id.in_(user_project_subquery))
        if project_id:
            count_q = count_q.where(Finding.project_id == project_id)
        if scan_id:
            count_q = count_q.where(Finding.scan_id == scan_id)
        count_res = await self.db.execute(count_q.group_by(func.lower(Finding.severity)))
        severity_counts = {sev: count for sev, count in count_res.all()}

        query = select(Finding).where(Finding.project_id.in_(user_project_subquery))
        if project_id:
            query = query.where(Finding.project_id == project_id)
        if scan_id:
            query = query.where(Finding.scan_id == scan_id)
        if severity:
            query = query.where(func.lower(Finding.severity) == severity.lower())
        if params.search:
            search = f"%{params.search.lower()}%"
            query = query.where(or_(func.lower(Finding.title).like(search), func.lower(Finding.description).like(search), func.lower(Finding.cwe_id).like(search), func.lower(Finding.owasp_category).like(search)))

        total_result = await self.db.execute(select(func.count()).select_from(query.subquery()))
        total = int(total_result.scalar_one() or 0)
        severity_rank = case(
            (func.lower(Finding.severity) == "critical", 5),
            (func.lower(Finding.severity) == "high", 4),
            (func.lower(Finding.severity) == "medium", 3),
            (func.lower(Finding.severity) == "low", 2),
            (func.lower(Finding.severity) == "info", 1),
            else_=0,
        )
        query = query.order_by(severity_rank.desc(), Finding.cvss_score.desc(), Finding.created_at.desc()).offset((params.page - 1) * params.page_size).limit(params.page_size)
        result = await self.db.execute(query)
        findings = [self._to_read(row) for row in result.scalars().all()]
        return {
            "items": findings,
            "page": params.page,
            "page_size": params.page_size,
            "total": total,
            "severity_counts": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "info": severity_counts.get("info", 0),
            }
        }

    def _to_read(self, finding: Finding) -> FindingRead:
        return FindingRead.model_validate(finding)
