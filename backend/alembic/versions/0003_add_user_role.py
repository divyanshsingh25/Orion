"""Add user role column and bootstrap admin role

Revision ID: 0003_add_user_role
Revises: 0002_user_and_google_auth
Create Date: 2026-09-05 09:25:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0003_add_user_role"
down_revision = "0002_user_and_google_auth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add role column with default 'user'
    op.add_column("users", sa.Column("role", sa.String(length=32), server_default="user", nullable=False))

    # 2. Ensure admin user has role 'admin' and is_verified = True
    bind = op.get_bind()
    bind.execute(
        sa.text(
            "UPDATE users SET role = 'admin', is_verified = true "
            "WHERE email = 'admin@orion.sec' OR username = 'admin'"
        )
    )


def downgrade() -> None:
    op.drop_column("users", "role")
