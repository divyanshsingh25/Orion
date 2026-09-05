import asyncio
import os
import sys
from datetime import UTC, datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database.session import AsyncSessionLocal
from app.models import Project, Scan, Target, User
from app.schemas.scan import ScanCreateRequest
from app.services.scan_service import ScanService, _get_telemetry_bucket, _live_telemetry_cache
from sqlalchemy import select


async def test_live_scan_lifecycle():
    print("[TEST] Starting Live Scan Persistence & Reconnection Test...")

    async with AsyncSessionLocal() as db:
        # Fetch admin user
        user_res = await db.execute(select(User).where(User.email == "admin@orion.sec"))
        user = user_res.scalars().first()
        if not user:
            user_res = await db.execute(select(User).where(User.is_verified == True))
            user = user_res.scalars().first()
        if not user:
            print("[SKIP] No verified test user in database.")
            return

        from app.models.project import Project
        # Fetch target belonging to user
        target_res = await db.execute(
            select(Target).join(Project, Target.project_id == Project.id).where(Project.user_id == user.id).limit(1)
        )
        target = target_res.scalars().first()
        if not target:
            target_res = await db.execute(select(Target).limit(1))
            target = target_res.scalars().first()
        if not target:
            print("[SKIP] No test target in database.")
            return

        service = ScanService(db)

        # 1. Create a Scan
        payload = ScanCreateRequest(
            target_id=target.id,
            scan_type="quick",
            depth="low",
        )
        scan_read = await service.create_scan(user, payload)
        scan_id = scan_read.id
        print(f"[TEST] Created scan {scan_id} (status: {scan_read.status})")

        # 2. Verify _get_telemetry_bucket initialized
        bucket = _get_telemetry_bucket(scan_id)
        bucket["target_url"] = target.url
        bucket["events"].append({
            "time": "12:00:00",
            "level": "INFO",
            "message": "Probe started on test endpoint",
        })
        bucket["modules"]["xss"] = {
            "name": "XSS Injection",
            "status": "Scanning",
            "progress": 45,
            "findings": 2,
        }
        bucket["eta_seconds"] = 120

        # 3. Test get_active_scan
        # Mark scan as running in DB
        scan_db_res = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan_db = scan_db_res.scalar_one()
        scan_db.status = "running"
        scan_db.progress_percent = 45
        await db.commit()

        active = await service.get_active_scan(user)
        assert active is not None, "get_active_scan should return active running scan"
        assert active.id == scan_id, f"Expected {scan_id}, got {active.id}"
        assert active.progress_percent == 45
        assert len(active.live_events) > 0, "live_events should be populated"
        assert active.live_events[0].message == "Probe started on test endpoint"
        assert len(active.live_modules) > 0, "live_modules should be populated"
        assert active.live_modules[0].name == "XSS Injection"
        assert active.eta_seconds == 120
        print("[TEST] PASS: get_active_scan returned running scan with populated telemetry.")

        # 4. Test get_scan directly
        retrieved = await service.get_scan(user, scan_id)
        assert retrieved.id == scan_id
        assert retrieved.target_url is not None
        assert retrieved.target_url == target.url
        print(f"[TEST] PASS: get_scan returned canonical target_url: {retrieved.target_url}")

        # 5. Test scan cancellation persistence
        cancelled = await service.cancel_scan(user, scan_id)
        assert cancelled.status == "cancelled"
        assert cancelled.id == scan_id
        print("[TEST] PASS: cancel_scan correctly persisted cancelled state.")

        # Clean up in-memory telemetry for test
        _live_telemetry_cache.pop(scan_id, None)

    print("\n[SUCCESS] ALL LIVE SCAN PERSISTENCE TESTS PASSED CLEANLY!\n")


if __name__ == "__main__":
    asyncio.run(test_live_scan_lifecycle())
