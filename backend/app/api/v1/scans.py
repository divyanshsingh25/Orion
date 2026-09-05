from __future__ import annotations

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.core.security import decode_token
from app.database.session import AsyncSessionLocal, get_db
from app.middleware.websocket_manager import connection_manager
from app.models import User
from app.schemas.common import MessageResponse
from app.schemas.scan import ScanCreateRequest, ScanRead
from app.services.scan_service import ScanService


router = APIRouter(prefix="/scans")


@router.get("", response_model=list[ScanRead])
async def list_scans(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await ScanService(db).list_scans(current_user)


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan(payload: ScanCreateRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await ScanService(db).create_scan(current_user, payload)


@router.get("/active", response_model=ScanRead | None)
async def get_active_scan(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await ScanService(db).get_active_scan(current_user)


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan(scan_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await ScanService(db).get_scan(current_user, scan_id)


@router.post("/{scan_id}/cancel", response_model=ScanRead)
async def cancel_scan(scan_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await ScanService(db).cancel_scan(current_user, scan_id)


@router.websocket("/ws/{scan_id}")
async def scan_stream(websocket: WebSocket, scan_id: str, token: str = Query(...)):
    try:
        payload = decode_token(token)
        if payload.get("typ") != "access":
            await websocket.close(code=4401)
            return
        user_id = payload.get("sub")
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if user is None or not user.is_active or not user.is_verified:
                await websocket.close(code=4403)
                return
    except Exception:
        await websocket.close(code=4401)
        return

    await connection_manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connection_manager.disconnect(scan_id, websocket)
    except Exception:
        connection_manager.disconnect(scan_id, websocket)
