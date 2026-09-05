"""Add username and Google authentication fields to users table

Revision ID: 0002_add_username_and_google_auth
Revises: 0001_initial_schema
Create Date: 2026-09-04 22:20:00.000000
"""

from __future__ import annotations

import re
from alembic import op
import sqlalchemy as sa


revision = "0002_user_and_google_auth"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add new columns
    op.add_column("users", sa.Column("username", sa.String(length=100), nullable=True))
    op.add_column("users", sa.Column("auth_provider", sa.String(length=32), server_default="email", nullable=False))
    op.add_column("users", sa.Column("google_id", sa.String(length=255), nullable=True))
    op.add_column("users", sa.Column("avatar_url", sa.Text(), nullable=True))

    # 2. Make password_hash nullable (for Google-authenticated users)
    op.alter_column("users", "password_hash", existing_type=sa.Text(), nullable=True)

    # 3. Backfill collision-safe usernames for existing users
    bind = op.get_bind()
    users_result = bind.execute(sa.text("SELECT id, email FROM users ORDER BY created_at ASC"))
    users = users_result.fetchall()

    used_usernames: set[str] = set()
    for row in users:
        user_id, email = row[0], row[1]
        raw_prefix = (email or "user").split("@")[0].lower()
        cleaned = re.sub(r"[^a-z0-9_.-]", "", raw_prefix)
        if not cleaned or len(cleaned) < 3:
            cleaned = f"user_{cleaned}" if cleaned else "user"

        candidate = cleaned
        counter = 2
        while candidate in used_usernames:
            candidate = f"{cleaned}{counter}"
            counter += 1

        used_usernames.add(candidate)
        bind.execute(
            sa.text("UPDATE users SET username = :uname WHERE id = :uid"),
            {"uname": candidate, "uid": user_id},
        )

    # 4. Add unique indexes
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_google_id", "users", ["google_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_google_id", table_name="users")
    op.drop_index("ix_users_username", table_name="users")
    op.alter_column("users", "password_hash", existing_type=sa.Text(), nullable=False)
    op.drop_column("users", "avatar_url")
    op.drop_column("users", "google_id")
    op.drop_column("users", "auth_provider")
    op.drop_column("users", "username")
