"""Add organization column to users table

Revision ID: 0004_add_organization_to_users
Revises: 0003_add_user_role
Create Date: 2026-09-05 10:55:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0004_add_organization_to_users"
down_revision = "0003_add_user_role"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("organization", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "organization")
