from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from sqlalchemy import select

from app.core.config import get_settings
from app.core.security import hash_password
from app.database.init_db import init_database
from app.database.session import AsyncSessionLocal, async_engine
from app.models import Project, Scan, Target, User
from app.schemas.project import ProjectCreate
from app.schemas.target import TargetCreate
from app.services.project_service import ProjectService
from app.services.target_service import TargetService
from app.services.scan_service import ScanService


DEFAULT_EMAIL = "admin@orion.sec"
DEFAULT_PASSWORD = "OrionDemo123!"
DEFAULT_PROJECT = "ORION Demo Project"
DEFAULT_TARGET = "https://example.com"


async def seed(email: str, password: str, full_name: str, project_name: str, target_url: str, run_scan: bool) -> None:
    await init_database(async_engine)

    async with AsyncSessionLocal() as db:
        user = await _get_or_create_user(db, email, password, full_name)
        project = await _get_or_create_project(db, user, project_name)
        target = await _get_or_create_target(db, user, project.id, target_url)

        print(f"Seeded user: {user.email}")
        print(f"Seeded project: {project.name}")
        print(f"Seeded target: {target.url}")

        if run_scan:
            print(f"Launching real scan for {target.url} ...")
            scan = Scan(project_id=project.id, target_id=target.id, user_id=user.id, scan_type="smart", status="queued", progress_percent=0, total_findings=0)
            db.add(scan)
            await db.commit()
            await db.refresh(scan)
            await ScanService(db).run_scan(scan.id)
            print(f"Scan completed: {scan.id}")


async def _get_or_create_user(db, email: str, password: str, full_name: str) -> User:
    result = await db.execute(select(User).where(User.email == email.lower()))
    user = result.scalar_one_or_none()
    if user:
        user.full_name = full_name
        user.password_hash = hash_password(password)
        user.is_active = True
        user.is_verified = True
        await db.commit()
        return user

    user = User(email=email.lower(), full_name=full_name, password_hash=hash_password(password), is_active=True, is_verified=True)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def _get_or_create_project(db, user: User, project_name: str) -> Project:
    service = ProjectService(db)
    result = await db.execute(select(Project).where(Project.user_id == user.id, Project.name == project_name))
    project = result.scalar_one_or_none()
    if project:
        return project
    return await service.create_project(user, ProjectCreate(name=project_name, description="Seeded ORION demo project"))


async def _get_or_create_target(db, user: User, project_id: str, target_url: str) -> Target:
    service = TargetService(db)
    result = await db.execute(select(Target).where(Target.project_id == project_id, Target.url == target_url))
    target = result.scalar_one_or_none()
    if target:
        return target
    return await service.create_target(user, TargetCreate(project_id=project_id, url=target_url))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed ORION demo data")
    parser.add_argument("--email", default=DEFAULT_EMAIL)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--full-name", default="ORION Administrator")
    parser.add_argument("--project-name", default=DEFAULT_PROJECT)
    parser.add_argument("--target-url", default=DEFAULT_TARGET)
    parser.add_argument("--run-scan", action="store_true", help="Run a real scan against the seeded target")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    asyncio.run(seed(args.email, args.password, args.full_name, args.project_name, args.target_url, args.run_scan))


if __name__ == "__main__":
    main()
