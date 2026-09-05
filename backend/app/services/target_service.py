from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Target, User
from app.schemas.target import TargetCreate, TargetRead
from app.services.project_service import ProjectService
from app.utils.validators import parse_and_validate_target


class TargetService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.project_service = ProjectService(db)

    async def create_target(self, user: User, payload: TargetCreate) -> TargetRead:
        await self.project_service.get_project(user, payload.project_id)
        parsed = parse_and_validate_target(payload.url)
        target = Target(project_id=payload.project_id, url=parsed.url, scheme=parsed.scheme, host=parsed.host, port=parsed.port, status="active", is_active=True)
        self.db.add(target)
        await self.db.commit()
        await self.db.refresh(target)
        return self._to_read(target)

    async def list_targets(self, user: User, project_id: str | None = None) -> list[TargetRead]:
        query = select(Target).join(Target.project).where(Target.project.has(user_id=user.id))
        if project_id:
            query = query.where(Target.project_id == project_id)
        result = await self.db.execute(query.order_by(Target.created_at.desc()))
        return [self._to_read(target) for target in result.scalars().all()]

    async def get_target(self, user: User, target_id: str) -> Target:
        result = await self.db.execute(select(Target).where(Target.id == target_id, Target.project.has(user_id=user.id)))
        target = result.scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
        return target

    def _to_read(self, target: Target) -> TargetRead:
        return TargetRead(id=target.id, project_id=target.project_id, url=target.url, scheme=target.scheme, host=target.host, port=target.port, status=target.status, risk_score=target.risk_score, validated_at=target.validated_at, created_at=target.created_at)
