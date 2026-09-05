from __future__ import annotations

import logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.database.base import Base
from app.models import *  # noqa: F403

logger = logging.getLogger("orion.db")


async def init_database(engine: AsyncEngine) -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        await _auto_migrate_columns(connection)


async def _auto_migrate_columns(connection) -> None:
    """Ensure any newly added model columns are present in existing database tables."""
    is_sqlite = connection.dialect.name == "sqlite"

    # List of (table_name, column_name, column_type_sql)
    required_columns = [
        # Scans table new columns
        ("scans", "auth_config_json", "TEXT" if is_sqlite else "JSON"),
        ("scans", "adaptive_json", "TEXT" if is_sqlite else "JSON"),
        ("scans", "correlation_json", "TEXT" if is_sqlite else "JSON"),
        ("scans", "recon_dns_json", "TEXT" if is_sqlite else "JSON"),
        ("scans", "recon_whois_json", "TEXT" if is_sqlite else "JSON"),
        ("scans", "recon_ports_json", "TEXT" if is_sqlite else "JSON"),
        ("scans", "recon_services_json", "TEXT" if is_sqlite else "JSON"),
        ("scans", "recon_os_json", "TEXT" if is_sqlite else "JSON"),
        ("scans", "endpoints_json", "TEXT" if is_sqlite else "JSON"),
        ("scans", "requests_count", "INTEGER DEFAULT 0"),
        ("scans", "endpoints_count", "INTEGER DEFAULT 0"),
        # Findings table new columns
        ("findings", "correlation_key", "VARCHAR(64)"),
        ("findings", "lifecycle_status", "VARCHAR(32) DEFAULT 'new'"),
        ("findings", "first_seen_scan_id", "VARCHAR(64)"),
        ("findings", "last_seen_scan_id", "VARCHAR(64)"),
        # AI Analysis table new columns
        ("ai_analysis", "verification_verdict", "VARCHAR(32) DEFAULT 'POTENTIAL'"),
        ("ai_analysis", "verification_reasoning", "TEXT"),
        ("ai_analysis", "verification_confidence", "NUMERIC(3, 2) DEFAULT 0.50"),
        # Users table new columns
        ("users", "username", "VARCHAR(100)"),
        ("users", "auth_provider", "VARCHAR(32) DEFAULT 'email'"),
        ("users", "google_id", "VARCHAR(255)"),
        ("users", "avatar_url", "TEXT"),
    ]

    for table_name, column_name, col_type in required_columns:
        try:
            if is_sqlite:
                check_sql = text(f"PRAGMA table_info({table_name})")
                result = await connection.execute(check_sql)
                columns = [row[1] for row in result.fetchall()]
                if columns and column_name not in columns:
                    logger.info("Migrating schema (SQLite): adding column %s.%s", table_name, column_name)
                    alter_sql = text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {col_type}")
                    await connection.execute(alter_sql)
            else:
                check_sql = text("SELECT column_name FROM information_schema.columns WHERE table_name = :tbl AND column_name = :col")
                result = await connection.execute(check_sql, {"tbl": table_name, "col": column_name})
                if not result.scalar_one_or_none():
                    logger.info("Migrating schema (PostgreSQL): adding column %s.%s", table_name, column_name)
                    alter_sql = text(f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {column_name} {col_type}")
                    await connection.execute(alter_sql)
        except Exception as err:
            logger.warning("Auto column migration check failed for %s.%s: %s", table_name, column_name, err)
