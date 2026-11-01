"""G4 incidents: incident, append-only incident_event, and the DEGRADED → UP pass counter.

Composite organization-scoped keys: incident → monitor, incident → organization_member
(assignee), incident_event → incident. A partial unique index allows at most one active incident
per (monitor, type). The app role may INSERT/SELECT incident events but never UPDATE or DELETE
them. Notification tables (channels, routes, outbox, deliveries) belong to G5. No incidents are
created.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-31
"""

from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinelops_app"
GRANTS = {
    "incident": "SELECT, INSERT, UPDATE",
    "incident_event": "SELECT, INSERT",
}


def _ts(name: str, *, nullable: bool = False) -> sa.Column[datetime]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.add_column(
        "monitor_health",
        sa.Column("consecutive_passes", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "incident",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("monitor_id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("source_kind", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("title_sanitized", sa.Text(), nullable=False),
        sa.Column("opened_measurement_id", sa.Uuid(), nullable=True),
        _ts("opened_at"),
        _ts("acknowledged_at", nullable=True),
        sa.Column("acknowledged_by", sa.Uuid(), nullable=True),
        _ts("resolved_at", nullable=True),
        sa.Column("resolved_by", sa.Uuid(), nullable=True),
        sa.Column("resolution", sa.Text(), nullable=True),
        sa.Column("assigned_user_id", sa.Uuid(), nullable=True),
        _ts("last_event_at"),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.UniqueConstraint("organization_id", "id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "assigned_user_id"],
            ["organization_member.organization_id", "organization_member.user_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["acknowledged_by"], ["app_user.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["resolved_by"], ["app_user.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("type IN ('OUTAGE', 'TLS_EXPIRY')", name="type_valid"),
        sa.CheckConstraint("source_kind IN ('HTTP_PROBE')", name="source_kind_valid"),
        sa.CheckConstraint("severity IN ('CRITICAL', 'WARNING')", name="severity_valid"),
        sa.CheckConstraint("status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')", name="status_valid"),
        sa.CheckConstraint(
            "resolution IS NULL OR resolution IN ('AUTO', 'MANUAL')", name="resolution_valid"
        ),
        sa.CheckConstraint(
            "(status = 'RESOLVED') = (resolved_at IS NOT NULL AND resolution IS NOT NULL)",
            name="resolved_consistent",
        ),
        sa.CheckConstraint(
            "resolution IS DISTINCT FROM 'MANUAL' OR resolved_by IS NOT NULL",
            name="manual_resolution_has_actor",
        ),
        sa.CheckConstraint(
            "status <> 'ACKNOWLEDGED' OR acknowledged_at IS NOT NULL",
            name="acknowledged_has_time",
        ),
    )
    op.create_index(
        "uq_incident_monitor_id_type_active",
        "incident",
        ["monitor_id", "type"],
        unique=True,
        postgresql_where=sa.text("status <> 'RESOLVED'"),
    )
    op.create_index(
        "ix_incident_organization_id_status_opened_at",
        "incident",
        ["organization_id", "status", "opened_at"],
    )
    op.create_index(
        "ix_incident_organization_id_monitor_id_opened_at",
        "incident",
        ["organization_id", "monitor_id", "opened_at"],
    )
    op.create_table(
        "incident_event",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("actor_kind", sa.Text(), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("details_sanitized_json", postgresql.JSONB(), nullable=False),
        _ts("created_at"),
        sa.UniqueConstraint("organization_id", "id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "incident_id"],
            ["incident.organization_id", "incident.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["app_user.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("actor_kind IN ('USER', 'SYSTEM')", name="actor_kind_valid"),
        sa.CheckConstraint(
            "actor_kind <> 'USER' OR actor_user_id IS NOT NULL", name="user_actor_has_id"
        ),
        sa.CheckConstraint(
            "event_type IN ('OPENED', 'ACKNOWLEDGED', 'ASSIGNED', 'UNASSIGNED', 'COMMENTED', "
            "'RESOLVED')",
            name="event_type_valid",
        ),
    )
    op.create_index(
        "ix_incident_event_organization_id_incident_id_created_at",
        "incident_event",
        ["organization_id", "incident_id", "created_at"],
    )
    op.create_index(
        "uq_incident_event_incident_id_event_type_lifecycle",
        "incident_event",
        ["incident_id", "event_type"],
        unique=True,
        postgresql_where=sa.text("event_type IN ('OPENED', 'ACKNOWLEDGED', 'RESOLVED')"),
    )
    for table, privileges in GRANTS.items():
        op.execute(f"GRANT {privileges} ON TABLE {table} TO {APP_ROLE}")


def downgrade() -> None:
    for table in GRANTS:
        op.execute(f"REVOKE ALL ON TABLE {table} FROM {APP_ROLE}")
    op.drop_table("incident_event")
    op.drop_table("incident")
    op.drop_column("monitor_health", "consecutive_passes")
