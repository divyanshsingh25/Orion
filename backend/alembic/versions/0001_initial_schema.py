"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-08-03 00:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_token_hash", sa.Text(), nullable=True),
        sa.Column("verification_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reset_token_hash", sa.Text(), nullable=True),
        sa.Column("reset_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_refresh_token_hash", sa.Text(), nullable=True),
        sa.Column("current_refresh_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # 2. projects
    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("scan_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("target_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_projects_user_id", "projects", ["user_id"], unique=False)

    # 3. targets
    op.create_table(
        "targets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("scheme", sa.String(length=16), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
        sa.Column("last_scan_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_targets_project_id", "targets", ["project_id"], unique=False)
    op.create_index("ix_targets_host", "targets", ["host"], unique=False)

    # 4. scans
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("scan_type", sa.String(length=64), nullable=False, server_default="full"),
        sa.Column("depth", sa.String(length=64), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("progress_percent", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("current_module", sa.String(length=128), nullable=True),
        sa.Column("current_url", sa.Text(), nullable=True),
        sa.Column("total_findings", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("statistics_json", sa.JSON(), nullable=True),
        sa.Column("summary_json", sa.JSON(), nullable=True),
        sa.Column("recon_dns_json", sa.JSON(), nullable=True),
        sa.Column("recon_whois_json", sa.JSON(), nullable=True),
        sa.Column("recon_ports_json", sa.JSON(), nullable=True),
        sa.Column("recon_services_json", sa.JSON(), nullable=True),
        sa.Column("recon_os_json", sa.JSON(), nullable=True),
        sa.Column("endpoints_json", sa.JSON(), nullable=True),
        sa.Column("requests_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("endpoints_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("auth_config_json", sa.JSON(), nullable=True),
        sa.Column("adaptive_json", sa.JSON(), nullable=True),
        sa.Column("correlation_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_project_id", "scans", ["project_id"], unique=False)
    op.create_index("ix_scans_target_id", "scans", ["target_id"], unique=False)
    op.create_index("ix_scans_user_id", "scans", ["user_id"], unique=False)
    op.create_index("ix_scans_status", "scans", ["status"], unique=False)

    # Circular FK targets.last_scan_id -> scans.id
    op.create_foreign_key(
        "fk_targets_last_scan_id_scans",
        "targets",
        "scans",
        ["last_scan_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # 5. findings
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("source_module", sa.String(length=128), nullable=False),
        sa.Column("finding_type", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("affected_url", sa.Text(), nullable=True),
        sa.Column("affected_parameter", sa.String(length=255), nullable=True),
        sa.Column("http_request", sa.Text(), nullable=True),
        sa.Column("http_response", sa.Text(), nullable=True),
        sa.Column("owasp_category", sa.String(length=128), nullable=False),
        sa.Column("cwe_id", sa.String(length=32), nullable=False),
        sa.Column("cwe_name", sa.String(length=255), nullable=False),
        sa.Column("cvss_score", sa.Numeric(precision=3, scale=1), nullable=False),
        sa.Column("cvss_vector", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("risk_rating", sa.String(length=32), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("best_practices", sa.Text(), nullable=True),
        sa.Column("secure_coding", sa.Text(), nullable=True),
        sa.Column("verification_guidance", sa.Text(), nullable=True),
        sa.Column("references_json", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("correlation_key", sa.String(length=64), nullable=True),
        sa.Column("lifecycle_status", sa.String(length=32), nullable=True, server_default="new"),
        sa.Column("first_seen_scan_id", sa.String(length=64), nullable=True),
        sa.Column("last_seen_scan_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_finding_type", "findings", ["finding_type"], unique=False)
    op.create_index("ix_findings_project_id", "findings", ["project_id"], unique=False)
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"], unique=False)
    op.create_index("ix_findings_severity", "findings", ["severity"], unique=False)
    op.create_index("ix_findings_source_module", "findings", ["source_module"], unique=False)
    op.create_index("ix_findings_target_id", "findings", ["target_id"], unique=False)
    op.create_index("ix_findings_correlation_key", "findings", ["correlation_key"], unique=False)

    # 6. ai_analysis
    op.create_table(
        "ai_analysis",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=True),
        sa.Column("simple_explanation", sa.Text(), nullable=False),
        sa.Column("technical_explanation", sa.Text(), nullable=False),
        sa.Column("business_impact", sa.Text(), nullable=False),
        sa.Column("risk_explanation", sa.Text(), nullable=False),
        sa.Column("owasp_explanation", sa.Text(), nullable=False),
        sa.Column("cwe_explanation", sa.Text(), nullable=False),
        sa.Column("remediation_steps_json", sa.JSON(), nullable=False),
        sa.Column("best_practices_json", sa.JSON(), nullable=False),
        sa.Column("secure_coding_recommendation", sa.Text(), nullable=False),
        sa.Column("verification_guidance", sa.Text(), nullable=False),
        sa.Column("code_example", sa.Text(), nullable=True),
        sa.Column("references_json", sa.JSON(), nullable=False),
        sa.Column("generated_by", sa.Text(), nullable=False, server_default="orion-ai"),
        sa.Column("verification_verdict", sa.String(length=32), nullable=True, server_default="POTENTIAL"),
        sa.Column("verification_reasoning", sa.Text(), nullable=True),
        sa.Column("verification_confidence", sa.Numeric(precision=3, scale=2), nullable=True, server_default=sa.text("0.50")),
        sa.Column("context_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id"),
    )
    op.create_index("ix_ai_analysis_scan_id", "ai_analysis", ["scan_id"], unique=False)

    # 7. reports
    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("report_format", sa.String(length=16), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("executive_summary", sa.Text(), nullable=False),
        sa.Column("overall_risk_score", sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column("severity_distribution_json", sa.JSON(), nullable=False),
        sa.Column("owasp_breakdown_json", sa.JSON(), nullable=False),
        sa.Column("cwe_mapping_json", sa.JSON(), nullable=False),
        sa.Column("cvss_analysis_json", sa.JSON(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_reports_project_id", "reports", ["project_id"], unique=False)
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"], unique=False)
    op.create_index("ix_reports_target_id", "reports", ["target_id"], unique=False)

    # 8. notifications
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=True),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_notifications_user_id", "notifications", ["user_id"], unique=False)

    # 9. activity_logs
    op.create_table(
        "activity_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=True),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("scan_id", sa.String(length=36), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_activity_logs_action", "activity_logs", ["action"], unique=False)
    op.create_index("ix_activity_logs_user_id", "activity_logs", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_table("activity_logs")
    op.drop_table("notifications")
    op.drop_table("reports")
    op.drop_table("ai_analysis")
    op.drop_table("findings")
    op.drop_constraint("fk_targets_last_scan_id_scans", "targets", type_="foreignkey")
    op.drop_table("scans")
    op.drop_table("targets")
    op.drop_table("projects")
    op.drop_table("users")
