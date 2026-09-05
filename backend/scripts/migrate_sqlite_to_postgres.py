#!/usr/bin/env python3
"""ORION — SQLite to PostgreSQL Data Migration Utility

Safely migrates data from SQLite (orion.db) into PostgreSQL while preserving:
- Primary keys (UUIDs)
- All relationships and foreign key integrity
- Cryptographic password hashes
- JSON payloads (deserialized and re-encoded properly)
- Datetimes (converted to UTC-aware timestamptz)
- Booleans (0/1 -> True/False)
- Floating/Numeric values

The migration is idempotent and safely restartable.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import os
import shutil
import sqlite3
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

import asyncpg

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings


def parse_dt(val: Any) -> datetime.datetime | None:
    if val is None or val == "":
        return None
    if isinstance(val, datetime.datetime):
        return val if val.tzinfo else val.replace(tzinfo=datetime.timezone.utc)
    s = str(val).strip()
    try:
        # Normalize ISO strings
        cleaned = s.replace(" ", "T")
        if not cleaned.endswith("Z") and "+" not in cleaned[10:] and "-" not in cleaned[10:]:
            cleaned += "+00:00"
        return datetime.datetime.fromisoformat(cleaned)
    except Exception:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.datetime.strptime(s[:26], fmt)
                return dt.replace(tzinfo=datetime.timezone.utc)
            except Exception:
                continue
    return None


def parse_json(val: Any) -> Any:
    if val is None or val == "":
        return None
    if isinstance(val, (dict, list)):
        return val
    try:
        return json.loads(str(val))
    except Exception:
        return None


def parse_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        return val.lower() in ("true", "1", "t", "yes", "y")
    return bool(val)


def parse_float(val: Any) -> float | None:
    if val is None or val == "":
        return None
    try:
        return float(val)
    except Exception:
        return None


def parse_decimal(val: Any) -> Decimal | None:
    if val is None or val == "":
        return None
    try:
        return Decimal(str(val))
    except Exception:
        return None


def create_backup(sqlite_path: Path) -> Path:
    backup_dir = BACKEND_ROOT / "storage" / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"orion.db.backup.{timestamp}"
    shutil.copy2(sqlite_path, backup_path)
    print(f"[BACKUP] Created backup: {backup_path} ({backup_path.stat().st_size:,} bytes)")
    return backup_path


async def migrate_data(sqlite_path: Path, pg_url: str, dry_run: bool = False) -> dict[str, dict[str, int]]:
    print(f"[INIT] Connecting to SQLite: {sqlite_path}")
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row
    s_cur = sqlite_conn.cursor()

    # Convert SQLAlchemy asyncpg URL to pure postgresql:// for asyncpg
    asyncpg_url = pg_url.replace("postgresql+asyncpg://", "postgresql://").replace("postgresql+psycopg://", "postgresql://")
    print(f"[INIT] Connecting to PostgreSQL...")
    pg_conn = await asyncpg.connect(asyncpg_url)

    # Register JSON codec with asyncpg
    await pg_conn.set_type_codec(
        "json",
        encoder=json.dumps,
        decoder=json.loads,
        schema="pg_catalog"
    )

    stats: dict[str, dict[str, int]] = {}

    try:
        # 1. Migrate users
        print("\n--- Migrating 'users' ---")
        s_cur.execute("SELECT * FROM users")
        user_rows = s_cur.fetchall()
        print(f"SQLite users count: {len(user_rows)}")
        migrated_users = 0
        for r in user_rows:
            if not dry_run:
                await pg_conn.execute(
                    """
                    INSERT INTO users (
                        id, email, full_name, password_hash, is_active, is_verified,
                        email_verified_at, verification_token_hash, verification_token_expires_at,
                        reset_token_hash, reset_token_expires_at, current_refresh_token_hash,
                        current_refresh_token_expires_at, created_at, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                    ON CONFLICT (id) DO UPDATE SET
                        email = EXCLUDED.email,
                        full_name = EXCLUDED.full_name,
                        password_hash = EXCLUDED.password_hash,
                        is_active = EXCLUDED.is_active,
                        is_verified = EXCLUDED.is_verified,
                        email_verified_at = EXCLUDED.email_verified_at,
                        updated_at = EXCLUDED.updated_at
                    """,
                    r["id"], r["email"], r["full_name"], r["password_hash"],
                    parse_bool(r["is_active"]), parse_bool(r["is_verified"]),
                    parse_dt(r["email_verified_at"]), r["verification_token_hash"],
                    parse_dt(r["verification_token_expires_at"]), r["reset_token_hash"],
                    parse_dt(r["reset_token_expires_at"]), r["current_refresh_token_hash"],
                    parse_dt(r["current_refresh_token_expires_at"]),
                    parse_dt(r["created_at"]) or datetime.datetime.now(datetime.timezone.utc),
                    parse_dt(r["updated_at"])
                )
            migrated_users += 1
        stats["users"] = {"sqlite": len(user_rows), "migrated": migrated_users}

        # 2. Migrate projects
        print("\n--- Migrating 'projects' ---")
        s_cur.execute("SELECT * FROM projects")
        project_rows = s_cur.fetchall()
        print(f"SQLite projects count: {len(project_rows)}")
        migrated_projects = 0
        for r in project_rows:
            if not dry_run:
                await pg_conn.execute(
                    """
                    INSERT INTO projects (
                        id, user_id, name, description, scan_count, target_count,
                        risk_score, created_at, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    ON CONFLICT (id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        scan_count = EXCLUDED.scan_count,
                        target_count = EXCLUDED.target_count,
                        risk_score = EXCLUDED.risk_score,
                        updated_at = EXCLUDED.updated_at
                    """,
                    r["id"], r["user_id"], r["name"], r["description"],
                    int(r["scan_count"] or 0), int(r["target_count"] or 0),
                    parse_float(r["risk_score"]) or 0.0,
                    parse_dt(r["created_at"]) or datetime.datetime.now(datetime.timezone.utc),
                    parse_dt(r["updated_at"])
                )
            migrated_projects += 1
        stats["projects"] = {"sqlite": len(project_rows), "migrated": migrated_projects}

        # 3. Migrate targets (initially last_scan_id = None to break circular FK)
        print("\n--- Migrating 'targets' (Phase A: initial load) ---")
        s_cur.execute("SELECT * FROM targets")
        target_rows = s_cur.fetchall()
        print(f"SQLite targets count: {len(target_rows)}")
        migrated_targets = 0
        target_last_scans: dict[str, str] = {}
        for r in target_rows:
            if r["last_scan_id"]:
                target_last_scans[r["id"]] = r["last_scan_id"]
            if not dry_run:
                await pg_conn.execute(
                    """
                    INSERT INTO targets (
                        id, project_id, url, scheme, host, port, status, is_active,
                        validated_at, risk_score, last_scan_id, created_at, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, $11, $12)
                    ON CONFLICT (id) DO UPDATE SET
                        url = EXCLUDED.url,
                        scheme = EXCLUDED.scheme,
                        host = EXCLUDED.host,
                        port = EXCLUDED.port,
                        status = EXCLUDED.status,
                        is_active = EXCLUDED.is_active,
                        validated_at = EXCLUDED.validated_at,
                        risk_score = EXCLUDED.risk_score,
                        updated_at = EXCLUDED.updated_at
                    """,
                    r["id"], r["project_id"], r["url"], r["scheme"], r["host"],
                    int(r["port"]) if r["port"] is not None else None,
                    r["status"] or "active", parse_bool(r["is_active"]),
                    parse_dt(r["validated_at"]), parse_float(r["risk_score"]) or 0.0,
                    parse_dt(r["created_at"]) or datetime.datetime.now(datetime.timezone.utc),
                    parse_dt(r["updated_at"])
                )
            migrated_targets += 1
        stats["targets"] = {"sqlite": len(target_rows), "migrated": migrated_targets}

        # 4. Migrate scans
        print("\n--- Migrating 'scans' ---")
        s_cur.execute("SELECT * FROM scans")
        scan_rows = s_cur.fetchall()
        print(f"SQLite scans count: {len(scan_rows)}")
        migrated_scans = 0
        for r in scan_rows:
            keys = r.keys()
            req_cnt = int(r["requests_count"]) if "requests_count" in keys and r["requests_count"] is not None else 0
            ep_cnt = int(r["endpoints_count"]) if "endpoints_count" in keys and r["endpoints_count"] is not None else 0
            auth_cfg = parse_json(r["auth_config_json"]) if "auth_config_json" in keys else None
            adapt_json = parse_json(r["adaptive_json"]) if "adaptive_json" in keys else None
            corr_json = parse_json(r["correlation_json"]) if "correlation_json" in keys else None
            recon_dns = parse_json(r["recon_dns_json"]) if "recon_dns_json" in keys else None
            recon_whois = parse_json(r["recon_whois_json"]) if "recon_whois_json" in keys else None
            recon_ports = parse_json(r["recon_ports_json"]) if "recon_ports_json" in keys else None
            recon_svcs = parse_json(r["recon_services_json"]) if "recon_services_json" in keys else None
            recon_os = parse_json(r["recon_os_json"]) if "recon_os_json" in keys else None
            ep_json = parse_json(r["endpoints_json"]) if "endpoints_json" in keys else None
            depth_val = r["depth"] if "depth" in keys and r["depth"] else "medium"

            if not dry_run:
                await pg_conn.execute(
                    """
                    INSERT INTO scans (
                        id, project_id, target_id, user_id, scan_type, depth, status,
                        progress_percent, current_module, current_url, total_findings,
                        started_at, completed_at, duration_seconds, error_message,
                        statistics_json, summary_json, recon_dns_json, recon_whois_json,
                        recon_ports_json, recon_services_json, recon_os_json, endpoints_json,
                        requests_count, endpoints_count, auth_config_json, adaptive_json,
                        correlation_json, created_at, updated_at
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                        $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
                        $27, $28, $29, $30
                    )
                    ON CONFLICT (id) DO UPDATE SET
                        status = EXCLUDED.status,
                        progress_percent = EXCLUDED.progress_percent,
                        current_module = EXCLUDED.current_module,
                        total_findings = EXCLUDED.total_findings,
                        completed_at = EXCLUDED.completed_at,
                        duration_seconds = EXCLUDED.duration_seconds,
                        statistics_json = EXCLUDED.statistics_json,
                        summary_json = EXCLUDED.summary_json,
                        updated_at = EXCLUDED.updated_at
                    """,
                    r["id"], r["project_id"], r["target_id"], r["user_id"],
                    r["scan_type"] or "full", depth_val, r["status"] or "queued",
                    int(r["progress_percent"] or 0), r["current_module"], r["current_url"],
                    int(r["total_findings"] or 0), parse_dt(r["started_at"]),
                    parse_dt(r["completed_at"]), parse_float(r["duration_seconds"]),
                    r["error_message"], parse_json(r["statistics_json"]),
                    parse_json(r["summary_json"]), recon_dns, recon_whois,
                    recon_ports, recon_svcs, recon_os, ep_json, req_cnt, ep_cnt,
                    auth_cfg, adapt_json, corr_json,
                    parse_dt(r["created_at"]) or datetime.datetime.now(datetime.timezone.utc),
                    parse_dt(r["updated_at"])
                )
            migrated_scans += 1
        stats["scans"] = {"sqlite": len(scan_rows), "migrated": migrated_scans}

        # 4b. Update targets last_scan_id now that scans are in place
        print("\n--- Updating 'targets.last_scan_id' ---")
        for target_id, last_scan_id in target_last_scans.items():
            if not dry_run:
                await pg_conn.execute(
                    "UPDATE targets SET last_scan_id = $1 WHERE id = $2",
                    last_scan_id, target_id
                )
        print(f"Updated last_scan_id for {len(target_last_scans)} targets.")

        # 5. Migrate findings
        print("\n--- Migrating 'findings' ---")
        s_cur.execute("SELECT * FROM findings")
        finding_rows = s_cur.fetchall()
        print(f"SQLite findings count: {len(finding_rows)}")
        migrated_findings = 0
        for r in finding_rows:
            keys = r.keys()
            corr_key = r["correlation_key"] if "correlation_key" in keys else None
            life_stat = r["lifecycle_status"] if "lifecycle_status" in keys else "new"
            first_seen = r["first_seen_scan_id"] if "first_seen_scan_id" in keys else None
            last_seen = r["last_seen_scan_id"] if "last_seen_scan_id" in keys else None

            if not dry_run:
                await pg_conn.execute(
                    """
                    INSERT INTO findings (
                        id, scan_id, project_id, target_id, source_module, finding_type,
                        title, description, evidence, affected_url, affected_parameter,
                        http_request, http_response, owasp_category, cwe_id, cwe_name,
                        cvss_score, cvss_vector, severity, confidence, risk_rating,
                        remediation, best_practices, secure_coding, verification_guidance,
                        references_json, status, metadata_json, correlation_key,
                        lifecycle_status, first_seen_scan_id, last_seen_scan_id,
                        created_at, updated_at
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                        $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
                        $27, $28, $29, $30, $31, $32, $33, $34
                    )
                    ON CONFLICT (id) DO NOTHING
                    """,
                    r["id"], r["scan_id"], r["project_id"], r["target_id"],
                    r["source_module"], r["finding_type"], r["title"], r["description"],
                    r["evidence"], r["affected_url"], r["affected_parameter"],
                    r["http_request"], r["http_response"], r["owasp_category"],
                    r["cwe_id"], r["cwe_name"], parse_decimal(r["cvss_score"]) or Decimal("0.0"),
                    r["cvss_vector"], r["severity"], r["confidence"], r["risk_rating"],
                    r["remediation"], r["best_practices"], r["secure_coding"],
                    r["verification_guidance"], parse_json(r["references_json"]),
                    r["status"] or "open", parse_json(r["metadata_json"]),
                    corr_key, life_stat, first_seen, last_seen,
                    parse_dt(r["created_at"]) or datetime.datetime.now(datetime.timezone.utc),
                    parse_dt(r["updated_at"])
                )
            migrated_findings += 1
        stats["findings"] = {"sqlite": len(finding_rows), "migrated": migrated_findings}

        # 6. Migrate ai_analysis
        print("\n--- Migrating 'ai_analysis' ---")
        s_cur.execute("SELECT * FROM ai_analysis")
        ai_rows = s_cur.fetchall()
        print(f"SQLite ai_analysis count: {len(ai_rows)}")
        migrated_ai = 0
        for r in ai_rows:
            keys = r.keys()
            verdict = r["verification_verdict"] if "verification_verdict" in keys else "POTENTIAL"
            reasoning = r["verification_reasoning"] if "verification_reasoning" in keys else None
            conf = parse_decimal(r["verification_confidence"]) if "verification_confidence" in keys else Decimal("0.50")

            if not dry_run:
                await pg_conn.execute(
                    """
                    INSERT INTO ai_analysis (
                        id, scan_id, finding_id, simple_explanation, technical_explanation,
                        business_impact, risk_explanation, owasp_explanation, cwe_explanation,
                        remediation_steps_json, best_practices_json, secure_coding_recommendation,
                        verification_guidance, code_example, references_json, generated_by,
                        verification_verdict, verification_reasoning, verification_confidence,
                        context_json, created_at, updated_at
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                        $15, $16, $17, $18, $19, $20, $21, $22
                    )
                    ON CONFLICT (id) DO NOTHING
                    """,
                    r["id"], r["scan_id"], r["finding_id"], r["simple_explanation"],
                    r["technical_explanation"], r["business_impact"], r["risk_explanation"],
                    r["owasp_explanation"], r["cwe_explanation"],
                    parse_json(r["remediation_steps_json"]) or [],
                    parse_json(r["best_practices_json"]) or [],
                    r["secure_coding_recommendation"], r["verification_guidance"],
                    r["code_example"], parse_json(r["references_json"]) or [],
                    r["generated_by"] or "orion-ai", verdict, reasoning, conf,
                    parse_json(r["context_json"]),
                    parse_dt(r["created_at"]) or datetime.datetime.now(datetime.timezone.utc),
                    parse_dt(r["updated_at"])
                )
            migrated_ai += 1
        stats["ai_analysis"] = {"sqlite": len(ai_rows), "migrated": migrated_ai}

        # 7. Migrate reports
        print("\n--- Migrating 'reports' ---")
        s_cur.execute("SELECT * FROM reports")
        report_rows = s_cur.fetchall()
        print(f"SQLite reports count: {len(report_rows)}")
        migrated_reports = 0
        for r in report_rows:
            if not dry_run:
                await pg_conn.execute(
                    """
                    INSERT INTO reports (
                        id, scan_id, project_id, target_id, report_format, file_path,
                        file_size, executive_summary, overall_risk_score,
                        severity_distribution_json, owasp_breakdown_json, cwe_mapping_json,
                        cvss_analysis_json, generated_at, created_at, updated_at
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
                    )
                    ON CONFLICT (id) DO NOTHING
                    """,
                    r["id"], r["scan_id"], r["project_id"], r["target_id"],
                    r["report_format"], r["file_path"],
                    int(r["file_size"]) if r["file_size"] is not None else None,
                    r["executive_summary"], parse_decimal(r["overall_risk_score"]) or Decimal("0.0"),
                    parse_json(r["severity_distribution_json"]) or {},
                    parse_json(r["owasp_breakdown_json"]) or {},
                    parse_json(r["cwe_mapping_json"]) or {},
                    parse_json(r["cvss_analysis_json"]) or {},
                    parse_dt(r["generated_at"]) or datetime.datetime.now(datetime.timezone.utc),
                    parse_dt(r["created_at"]) or datetime.datetime.now(datetime.timezone.utc),
                    parse_dt(r["updated_at"])
                )
            migrated_reports += 1
        stats["reports"] = {"sqlite": len(report_rows), "migrated": migrated_reports}

        # 8. Migrate notifications
        print("\n--- Migrating 'notifications' ---")
        s_cur.execute("SELECT * FROM notifications")
        notif_rows = s_cur.fetchall()
        print(f"SQLite notifications count: {len(notif_rows)}")
        migrated_notifs = 0
        for r in notif_rows:
            if not dry_run:
                await pg_conn.execute(
                    """
                    INSERT INTO notifications (
                        id, user_id, kind, title, message, payload_json, read_at,
                        created_at, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    r["id"], r["user_id"], r["kind"], r["title"], r["message"],
                    parse_json(r["payload_json"]), parse_dt(r["read_at"]),
                    parse_dt(r["created_at"]) or datetime.datetime.now(datetime.timezone.utc),
                    parse_dt(r["updated_at"])
                )
            migrated_notifs += 1
        stats["notifications"] = {"sqlite": len(notif_rows), "migrated": migrated_notifs}

        # 9. Migrate activity_logs
        print("\n--- Migrating 'activity_logs' ---")
        s_cur.execute("SELECT * FROM activity_logs")
        act_rows = s_cur.fetchall()
        print(f"SQLite activity_logs count: {len(act_rows)}")
        migrated_act = 0
        for r in act_rows:
            if not dry_run:
                await pg_conn.execute(
                    """
                    INSERT INTO activity_logs (
                        id, user_id, project_id, target_id, scan_id, action,
                        ip_address, user_agent, metadata_json, created_at, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    r["id"], r["user_id"], r["project_id"], r["target_id"], r["scan_id"],
                    r["action"], r["ip_address"], r["user_agent"],
                    parse_json(r["metadata_json"]),
                    parse_dt(r["created_at"]) or datetime.datetime.now(datetime.timezone.utc),
                    parse_dt(r["updated_at"])
                )
            migrated_act += 1
        stats["activity_logs"] = {"sqlite": len(act_rows), "migrated": migrated_act}

    finally:
        sqlite_conn.close()
        await pg_conn.close()

    return stats


async def verify_parity(sqlite_path: Path, pg_url: str) -> bool:
    print("\n========================================================")
    print("           VERIFYING PARITY BETWEEN SQLITE & POSTGRESQL")
    print("========================================================")
    s_conn = sqlite3.connect(sqlite_path)
    s_cur = s_conn.cursor()

    asyncpg_url = pg_url.replace("postgresql+asyncpg://", "postgresql://").replace("postgresql+psycopg://", "postgresql://")
    pg_conn = await asyncpg.connect(asyncpg_url)

    tables = ["users", "projects", "targets", "scans", "findings", "ai_analysis", "reports", "notifications", "activity_logs"]
    all_matched = True

    print(f"{'Table':<20} | {'SQLite':<10} | {'PostgreSQL':<10} | {'Match?':<8}")
    print("-" * 55)

    for t in tables:
        s_cur.execute(f'SELECT count(*) FROM "{t}"')
        s_cnt = s_cur.fetchone()[0]

        pg_cnt = await pg_conn.fetchval(f'SELECT count(*) FROM "{t}"')
        matched = (s_cnt == pg_cnt)
        if not matched:
            all_matched = False
        print(f"{t:<20} | {s_cnt:<10} | {pg_cnt:<10} | {'PASS' if matched else 'FAIL':<8}")

    # Verify primary key matching for users, projects, scans, findings
    for t in ["users", "projects", "scans", "findings"]:
        s_cur.execute(f'SELECT id FROM "{t}" ORDER BY id')
        s_ids = set(r[0] for r in s_cur.fetchall())

        pg_rows = await pg_conn.fetch(f'SELECT id FROM "{t}" ORDER BY id')
        pg_ids = set(r["id"] for r in pg_rows)

        diff = s_ids.symmetric_difference(pg_ids)
        if diff:
            print(f"[ERROR] ID mismatch in {t}: {len(diff)} differing IDs")
            all_matched = False
        else:
            print(f"[OK] 100% ID parity confirmed for {t} ({len(s_ids)} IDs matched)")

    s_conn.close()
    await pg_conn.close()
    print("========================================================")
    if all_matched:
        print("[SUCCESS] ALL TABLES, RECORD COUNTS, AND PRIMARY KEYS MATCH 100%!")
    else:
        print("[FAILURE] DISCREPANCY DETECTED BETWEEN SQLITE AND POSTGRESQL!")
    print("========================================================\n")
    return all_matched


async def main() -> None:
    parser = argparse.ArgumentParser(description="ORION SQLite to PostgreSQL Migration")
    parser.add_argument("--sqlite-db", default=str(BACKEND_ROOT / "orion.db"), help="Path to SQLite orion.db")
    parser.add_argument("--verify-only", action="store_true", help="Only verify record parity without migrating")
    parser.add_argument("--no-backup", action="store_true", help="Skip creating SQLite backup")
    args = parser.parse_args()

    settings = get_settings()
    pg_url = settings.database_url
    sqlite_path = Path(args.sqlite_db).resolve()

    if not sqlite_path.exists():
        print(f"[ERROR] SQLite database not found at: {sqlite_path}")
        sys.exit(1)

    if not args.verify_only:
        if not args.no_backup:
            create_backup(sqlite_path)
        stats = await migrate_data(sqlite_path, pg_url)
        print("\nMigration pass completed.")

    parity_ok = await verify_parity(sqlite_path, pg_url)
    if not parity_ok:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
