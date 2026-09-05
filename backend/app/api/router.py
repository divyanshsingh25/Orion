from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.findings import router as findings_router
from app.api.v1.health import router as health_router
from app.api.v1.projects import router as projects_router
from app.api.v1.reports import router as reports_router
from app.api.v1.scans import router as scans_router
from app.api.v1.targets import router as targets_router
from app.api.v1.chat import router as chat_router


api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])
api_router.include_router(auth_router, tags=["auth"])
api_router.include_router(dashboard_router, tags=["dashboard"])
api_router.include_router(projects_router, tags=["projects"])
api_router.include_router(targets_router, tags=["targets"])
api_router.include_router(scans_router, tags=["scans"])
api_router.include_router(findings_router, tags=["findings"])
api_router.include_router(reports_router, tags=["reports"])
api_router.include_router(chat_router, prefix="/chat", tags=["chat"])
