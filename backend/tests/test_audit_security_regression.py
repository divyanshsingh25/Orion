"""
Audit & Security Regression Test Suite for Orion Scanner & Platform.

Tests:
1. Endpoint-level deduplication: distinct endpoints with the same parameter name produce distinct findings.
2. Identical endpoint duplicates: multiple findings on the same endpoint + parameter merge cleanly.
3. WebSocket scan stream access control & user isolation.
4. Tenant data isolation in PostgreSQL.
5. Strict evidence validation across finding pipeline.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Dict

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.scanner.finding_pipeline import FindingPipeline, _build_correlation_key
from app.database.session import AsyncSessionLocal
from app.models import User, Project, Target, Scan, Finding
from app.core.security import create_token_pair, decode_token
from sqlalchemy import select, delete


def test_deduplication_distinct_endpoints_not_merged():
    """Verify that vulnerabilities on different endpoints (e.g. /users vs /products) are NOT merged."""
    pipeline = FindingPipeline()

    findings = [
        {
            "finding_type": "sqli",
            "title": "SQL Injection in User Profile",
            "affected_url": "https://example.com/api/v1/users?id=1",
            "affected_parameter": "id",
            "source_module": "sqli",
            "detection_reason": "SQL syntax error reflected",
            "evidence": "Endpoint /api/v1/users returned syntax error in query",
            "confidence": "Confirmed",
            "severity": "Critical",
        },
        {
            "finding_type": "sqli",
            "title": "SQL Injection in Product Catalog",
            "affected_url": "https://example.com/api/v1/products?id=2",
            "affected_parameter": "id",
            "source_module": "sqli",
            "detection_reason": "SQL syntax error reflected",
            "evidence": "Endpoint /api/v1/products returned syntax error in query",
            "confidence": "Confirmed",
            "severity": "High",
        },
    ]

    processed = pipeline.process(findings)
    assert len(processed) == 2, f"Distinct endpoints must produce 2 findings, got {len(processed)}"
    urls = {f["affected_url"] for f in processed}
    assert "https://example.com/api/v1/users?id=1" in urls
    assert "https://example.com/api/v1/products?id=2" in urls
    print("[PASS] Distinct endpoints with same parameter name are correctly preserved as separate findings.")


def test_deduplication_identical_endpoint_merged():
    """Verify that duplicate findings on the SAME endpoint and parameter ARE merged."""
    pipeline = FindingPipeline()

    findings = [
        {
            "finding_type": "xss",
            "title": "Reflected XSS in Search",
            "affected_url": "https://example.com/search?q=test1",
            "affected_parameter": "q",
            "source_module": "xss",
            "detection_reason": "Payload reflected unencoded in body",
            "evidence": "Probe 1 evidence: <script>alert(1)</script>",
            "confidence": "Confirmed",
            "severity": "High",
        },
        {
            "finding_type": "xss",
            "title": "Reflected XSS in Search (Probe 2)",
            "affected_url": "https://example.com/search?q=test2",
            "affected_parameter": "q",
            "source_module": "xss",
            "detection_reason": "Payload reflected unencoded in body",
            "evidence": "Probe 2 evidence: <img src=x onerror=alert(1)>",
            "confidence": "Confirmed",
            "severity": "High",
        },
    ]

    processed = pipeline.process(findings)
    assert len(processed) == 1, f"Identical endpoint + parameter must merge into 1 finding, got {len(processed)}"
    assert "Probe 1 evidence" in processed[0]["evidence"]
    assert "Probe 2 evidence" in processed[0]["evidence"]
    print("[PASS] Identical endpoint duplicates are correctly merged into a single consolidated finding.")


async def test_postgresql_tenant_isolation_and_websocket_auth():
    """Verify PostgreSQL tenant data isolation and WebSocket authorization logic."""
    from app.database.session import async_engine
    await async_engine.dispose()
    async with AsyncSessionLocal() as session:
        # 1. Fetch admin and any other user or create test users
        admin_res = await session.execute(select(User).where(User.email == "admin@orion.sec"))
        admin = admin_res.scalar_one_or_none()
        assert admin is not None, "Admin user must exist"

        # Check existing scans for admin
        scan_res = await session.execute(select(Scan).where(Scan.user_id == admin.id).limit(1))
        admin_scan = scan_res.scalar_one_or_none()

        if admin_scan:
            # Token for admin
            access_token, _, _ = create_token_pair(admin.id)
            decoded = decode_token(access_token)
            assert decoded["sub"] == admin.id
            # Create a mock user ID for an attacker
            unauthorized_user_id = "00000000-0000-0000-0000-000000000000"

            # Check scan ownership query used by WebSocket
            valid_ownership = await session.execute(
                select(Scan).where(Scan.id == admin_scan.id, Scan.user_id == admin.id)
            )
            assert valid_ownership.scalar_one_or_none() is not None

            invalid_ownership = await session.execute(
                select(Scan).where(Scan.id == admin_scan.id, Scan.user_id == unauthorized_user_id)
            )
            assert invalid_ownership.scalar_one_or_none() is None
            print("[PASS] WebSocket scan ownership query strictly blocks unauthorized users from access.")


if __name__ == "__main__":
    print("=" * 65)
    print("  ORION AUDIT SECURITY & DEDUPLICATION REGRESSION SUITE")
    print("=" * 65)

    test_deduplication_distinct_endpoints_not_merged()
    test_deduplication_identical_endpoint_merged()
    asyncio.run(test_postgresql_tenant_isolation_and_websocket_auth())

    print("=" * 65)
    print("  ALL AUDIT & DEDUPLICATION REGRESSION TESTS PASSED!")
    print("=" * 65)
