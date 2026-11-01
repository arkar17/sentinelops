"""G3 catalog: verified domains, monitors, monitor schedules and health counters.

Composite organization-scoped keys: monitor → project, schedule/health → monitor. Grants DML
(no DELETE) to the existing sentinelops_app role. No monitors or domains are created.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-31
"""

import uuid
from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinelops_app"
GRANTS = {
    "verified_domain": "SELECT, INSERT, UPDATE",
    "monitor": "SELECT, INSERT, UPDATE",
    "monitor_schedule": "SELECT, INSERT, UPDATE",
    "monitor_health": "SELECT, INSERT, UPDATE",
}


def _ts(name: str, nullable: bool = False) -> sa.Column[datetime]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(name: str, target: str, nullable: bool = True) -> sa.Column[uuid.UUID]:
    return sa.Column(name, sa.Uuid(), sa.ForeignKey(target, ondelete="RESTRICT"), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "verified_domain",
        sa.Column("id", sa.Uuid(), primary_key=True),
        _fk("organization_id", "organization.id", nullable=False),
        sa.Column("fqdn", sa.Text(), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("challenge_token_hash", sa.Text(), nullable=True),
        _ts("challenge_expires_at", nullable=True),
        _ts("verified_at", nullable=True),
        _ts("expires_at", nullable=True),
        _ts("last_checked_at", nullable=True),
        sa.Column("exception_reason", sa.Text(), nullable=True),
        _fk("decided_by", "app_user.id"),
        _fk("created_by", "app_user.id", nullable=False),
        _ts("created_at"),
        _ts("updated_at"),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.UniqueConstraint("organization_id", "id"),
        sa.UniqueConstraint("organization_id", "fqdn"),
        sa.CheckConstraint("method IN ('DNS_TXT', 'ADMIN_EXCEPTION')", name="method_valid"),
        sa.CheckConstraint(
            "status IN ('PENDING', 'VERIFIED', 'EXPIRED', 'REJECTED', 'REVOKED')",
            name="status_valid",
        ),
        sa.CheckConstraint(
            "status <> 'VERIFIED' OR (verified_at IS NOT NULL AND expires_at IS NOT NULL)",
            name="verified_has_window",
        ),
    )
    op.create_table(
        "monitor",
        sa.Column("id", sa.Uuid(), primary_key=True),
        _fk("organization_id", "organization.id", nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("url_ciphertext", sa.Text(), nullable=False),
        sa.Column("url_key_id", sa.Text(), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("display_url", sa.Text(), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("timeout_ms", sa.Integer(), nullable=False),
        sa.Column("retry_attempts", sa.Integer(), nullable=False),
        sa.Column("expected_status_json", postgresql.JSONB(), nullable=False),
        sa.Column("validation_json", postgresql.JSONB(), nullable=True),
        sa.Column("header_ciphertext", sa.Text(), nullable=True),
        sa.Column("header_key_id", sa.Text(), nullable=True),
        sa.Column("header_count", sa.Integer(), nullable=False),
        sa.Column("latency_threshold_ms", sa.Integer(), nullable=True),
        sa.Column("failure_threshold", sa.Integer(), nullable=False),
        sa.Column("recovery_threshold", sa.Integer(), nullable=False),
        sa.Column("tls_warn_days", sa.Integer(), nullable=False),
        sa.Column("tags_json", postgresql.JSONB(), nullable=False),
        sa.Column("lifecycle", sa.Text(), nullable=False),
        sa.Column("paused_reason", sa.Text(), nullable=True),
        sa.Column("attention_reason", sa.Text(), nullable=True),
        _fk("created_by", "app_user.id", nullable=False),
        _ts("created_at"),
        _ts("updated_at"),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.UniqueConstraint("organization_id", "id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["project.organization_id", "project.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("kind = 'HTTP'", name="kind_http_phase1"),
        sa.CheckConstraint("method IN ('GET', 'HEAD')", name="method_valid"),
        sa.CheckConstraint("interval_seconds IN (60, 120, 300)", name="interval_allowed"),
        sa.CheckConstraint("timeout_ms BETWEEN 3000 AND 15000", name="timeout_range"),
        sa.CheckConstraint("retry_attempts BETWEEN 0 AND 2", name="retry_range"),
        sa.CheckConstraint("header_count BETWEEN 0 AND 5", name="header_count_range"),
        sa.CheckConstraint(
            "(header_count = 0) = (header_ciphertext IS NULL)", name="headers_consistent"
        ),
        sa.CheckConstraint(
            "validation_json IS NULL OR method = 'GET'", name="validation_needs_get"
        ),
        sa.CheckConstraint("failure_threshold BETWEEN 1 AND 10", name="failure_threshold_range"),
        sa.CheckConstraint("recovery_threshold BETWEEN 1 AND 10", name="recovery_threshold_range"),
        sa.CheckConstraint(
            "latency_threshold_ms IS NULL OR latency_threshold_ms BETWEEN 1 AND 15000",
            name="latency_threshold_range",
        ),
        sa.CheckConstraint("tls_warn_days BETWEEN 1 AND 90", name="tls_warn_days_range"),
        sa.CheckConstraint(
            "lifecycle IN ('DRAFT', 'ACTIVE', 'PAUSED', 'ARCHIVED')", name="lifecycle_valid"
        ),
        sa.CheckConstraint(
            "paused_reason IS NULL OR paused_reason IN ('USER', 'POLICY_BLOCKED')",
            name="paused_reason_valid",
        ),
    )
    op.create_index(
        "ix_monitor_organization_id_lifecycle", "monitor", ["organization_id", "lifecycle"]
    )
    op.create_table(
        "monitor_schedule",
        sa.Column("monitor_id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        _ts("next_due_at"),
        _ts("planned_due_at", nullable=True),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        _ts("lease_until", nullable=True),
        sa.Column("current_job_id", sa.Uuid(), nullable=True),
        sa.Column("current_trigger", sa.Text(), nullable=True),
        _ts("manual_check_requested_at", nullable=True),
        _ts("last_manual_check_requested_at", nullable=True),
        sa.Column("missed_slots", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("missed_slots >= 0", name="missed_slots_nonnegative"),
    )
    op.create_index("ix_monitor_schedule_next_due_at", "monitor_schedule", ["next_due_at"])
    op.create_table(
        "monitor_health",
        sa.Column("monitor_id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("consecutive_successes", sa.Integer(), nullable=False),
        sa.Column("consecutive_slow", sa.Integer(), nullable=False),
        sa.Column("consecutive_blocked", sa.Integer(), nullable=False),
        sa.Column("last_measurement_id", sa.Uuid(), nullable=True),
        _ts("last_conclusive_at", nullable=True),
        _ts("last_change_at", nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("state IN ('UNKNOWN', 'UP', 'DEGRADED', 'DOWN')", name="state_valid"),
    )
    for table, privileges in GRANTS.items():
        op.execute(f"GRANT {privileges} ON TABLE {table} TO {APP_ROLE}")


def downgrade() -> None:
    for table in GRANTS:
        op.execute(f"REVOKE ALL ON TABLE {table} FROM {APP_ROLE}")
    for table in ("monitor_health", "monitor_schedule", "monitor", "verified_domain"):
        op.drop_table(table)
