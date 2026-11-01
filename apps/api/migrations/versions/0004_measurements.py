"""G3 measurements: append-only check results and the hourly rollup table (filled from G6).

The app role may INSERT/SELECT measurements but not UPDATE them; retention DELETE is granted with
the G6 retention job. No measurements are created.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinelops_app"
GRANTS = {
    "measurement": "SELECT, INSERT",
    "hourly_monitor_rollup": "SELECT, INSERT, UPDATE",
}


def upgrade() -> None:
    op.create_table(
        "measurement",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("monitor_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("trigger", sa.Text(), nullable=False),
        sa.Column("source_kind", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.Text(), nullable=False),
        sa.Column("failure_category", sa.Text(), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("elapsed_ms", sa.Integer(), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("tls_not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("value_numeric", sa.Numeric(), nullable=True),
        sa.UniqueConstraint("organization_id", "id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "result IN ('PASS', 'SLOW', 'FAIL', 'BLOCKED', 'INCONCLUSIVE')", name="result_valid"
        ),
        sa.CheckConstraint("trigger IN ('SCHEDULED', 'MANUAL')", name="trigger_valid"),
        sa.CheckConstraint(
            "source_kind IN ('HTTP_PROBE', 'AGENT_METRIC')", name="source_kind_valid"
        ),
        sa.CheckConstraint("elapsed_ms IS NULL OR elapsed_ms >= 0", name="elapsed_nonnegative"),
        sa.CheckConstraint("attempt_count BETWEEN 1 AND 3", name="attempt_count_range"),
    )
    op.create_index(
        "uq_measurement_monitor_id_job_id",
        "measurement",
        ["monitor_id", "job_id"],
        unique=True,
        postgresql_where=sa.text("job_id IS NOT NULL"),
    )
    op.create_index(
        "ix_measurement_organization_id_monitor_id_observed_at",
        "measurement",
        ["organization_id", "monitor_id", "observed_at"],
    )
    op.create_table(
        "hourly_monitor_rollup",
        sa.Column("organization_id", sa.Uuid(), primary_key=True),
        sa.Column("monitor_id", sa.Uuid(), primary_key=True),
        sa.Column("window_start", sa.DateTime(timezone=True), primary_key=True),
        sa.Column("conclusive_samples", sa.Integer(), nullable=False),
        sa.Column("available_samples", sa.Integer(), nullable=False),
        sa.Column("failed_samples", sa.Integer(), nullable=False),
        sa.Column("blocked_samples", sa.Integer(), nullable=False),
        sa.Column("inconclusive_samples", sa.Integer(), nullable=False),
        sa.Column("missed_slots", sa.Integer(), nullable=False),
        sa.Column("latency_p50_ms", sa.Integer(), nullable=True),
        sa.Column("latency_p95_ms", sa.Integer(), nullable=True),
        sa.Column("downtime_seconds_est", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
    )
    for table, privileges in GRANTS.items():
        op.execute(f"GRANT {privileges} ON TABLE {table} TO {APP_ROLE}")


def downgrade() -> None:
    for table in GRANTS:
        op.execute(f"REVOKE ALL ON TABLE {table} FROM {APP_ROLE}")
    op.drop_table("hourly_monitor_rollup")
    op.drop_table("measurement")
