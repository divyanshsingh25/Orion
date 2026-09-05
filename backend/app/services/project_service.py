from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Project, User
from app.schemas.project import ProjectCreate, ProjectRead, ProjectUpdate


class ProjectService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create_project(self, user: User, payload: ProjectCreate) -> ProjectRead:
        project = Project(user_id=user.id, name=payload.name, description=payload.description)
        self.db.add(project)
        await self.db.commit()
        await self.db.refresh(project)
        return self._to_read(project)

    async def list_projects(self, user: User) -> list[ProjectRead]:
        result = await self.db.execute(select(Project).where(Project.user_id == user.id).order_by(Project.created_at.desc()))
        return [self._to_read(project) for project in result.scalars().all()]

    async def get_project(self, user: User, project_id: str) -> Project:
        result = await self.db.execute(select(Project).where(Project.id == project_id, Project.user_id == user.id))
        project = result.scalar_one_or_none()
        if project is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        return project

    async def update_project(self, user: User, project_id: str, payload: ProjectUpdate) -> ProjectRead:
        project = await self.get_project(user, project_id)
        if payload.name is not None:
            project.name = payload.name
        if payload.description is not None:
            project.description = payload.description
        await self.db.commit()
        await self.db.refresh(project)
        return self._to_read(project)

    def _to_read(self, project: Project) -> ProjectRead:
        return ProjectRead(id=project.id, user_id=project.user_id, name=project.name, description=project.description, scan_count=project.scan_count, target_count=project.target_count, risk_score=project.risk_score, created_at=project.created_at)
