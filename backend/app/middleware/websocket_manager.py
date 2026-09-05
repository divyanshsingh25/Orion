from __future__ import annotations

from collections.abc import Iterable

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = {}
        self._history: dict[str, list[dict]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.setdefault(scan_id, set()).add(websocket)

        # Replay historical logs/events so late joiners see what happened
        for payload in self._history.get(scan_id, []):
            try:
                await websocket.send_json(payload)
            except Exception:
                pass

    def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        connections = self._connections.get(scan_id)
        if not connections:
            return
        connections.discard(websocket)
        if not connections:
            self._connections.pop(scan_id, None)

    async def broadcast(self, scan_id: str, payload: dict) -> None:
        # Save important payloads (like logs and module updates) to history
        if "log" in payload or payload.get("event") in ("scan_started", "module_start", "module_complete"):
            history = self._history.setdefault(scan_id, [])
            history.append(payload)
            if len(history) > 1000:
                self._history[scan_id] = history[-1000:]

        connections = list(self._connections.get(scan_id, set()))
        for websocket in connections:
            try:
                await websocket.send_json(payload)
            except Exception:
                self.disconnect(scan_id, websocket)

    async def broadcast_many(self, scan_id: str, payloads: Iterable[dict]) -> None:
        for payload in payloads:
            await self.broadcast(scan_id, payload)


connection_manager = ConnectionManager()
