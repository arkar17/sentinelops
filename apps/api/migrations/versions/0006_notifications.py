"""G5 notifications: channels, email recipients, routes, transactional outbox, delivery history.

Composite organization-scoped keys on every reference (recipient → member, route → channel/
project/monitor, outbox → channel/incident/event/monitor, delivery → outbox). Telegram
credentials are stored only as ciphertext. Delivery history is append-only for the app role.
No channels or routes are created.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinelops_app"
EVENT_CHECK = (
    "event_type IN ('INCIDENT_OPENED', 'TLS_EXPIRY_WARNING', 'INCIDENT_ACKNOWLEDGED', "
    "'INCIDENT_RESOLVED', 'MONITOR_AUTO_PAUSED', 'CHANNEL_TEST')"
)
GRANTS = {
    "notification_channel": "SELECT, INSERT, UPDATE",
    "notification_channel_recipient": "SELECT, INSERT, DELETE",
    "notification_route": "SELECT, INSERT, UPDATE, DELETE",
    "notification_outbox": "SELECT, INSERT, UPDATE",
    "notification_delivery": "SELECT, INSERT",
}


def upgrade() -> None:
    op.create_table(
        "notification_channel",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("label", sa.Text(), nullable=False),
        sa.Column("config_ciphertext", sa.Text(), nullable=True),
        sa.Column("config_key_id", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "(type = 'TELEGRAM') = (config_ciphertext IS NOT NULL)",
            name=op.f("ck_notification_channel_telegram_has_config"),
        ),
        sa.CheckConstraint(
            "type IN ('TELEGRAM', 'EMAIL')", name=op.f("ck_notification_channel_type_valid")
        ),
        sa.CheckConstraint(
            "(config_ciphertext IS NULL) = (config_key_id IS NULL)",
            name=op.f("ck_notification_channel_config_consistent"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["app_user.id"],
            name=op.f("fk_notification_channel_created_by_app_user"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organization.id"],
            name=op.f("fk_notification_channel_organization_id_organization"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_channel")),
        sa.UniqueConstraint(
            "organization_id", "id", name=op.f("uq_notification_channel_organization_id_id")
        ),
    )
    op.create_index(
        "ix_notification_channel_organization_id",
        "notification_channel",
        ["organization_id"],
        unique=False,
    )
    op.create_table(
        "notification_channel_recipient",
        sa.Column("channel_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "channel_id"],
            ["notification_channel.organization_id", "notification_channel.id"],
            name=op.f(
                "fk_notification_channel_recipient_organization_id_channel_id_notification_channel"
            ),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["organization_member.organization_id", "organization_member.user_id"],
            name=op.f(
                "fk_notification_channel_recipient_organization_id_user_id_organization_member"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "channel_id", "user_id", name=op.f("pk_notification_channel_recipient")
        ),
    )
    op.create_table(
        "notification_route",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("channel_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("monitor_id", sa.Uuid(), nullable=True),
        sa.Column("event_types_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "jsonb_typeof(event_types_json) = 'array' AND jsonb_array_length(event_types_json) > 0",
            name=op.f("ck_notification_route_event_types_nonempty"),
        ),
        sa.CheckConstraint(
            "NOT (project_id IS NOT NULL AND monitor_id IS NOT NULL)",
            name=op.f("ck_notification_route_single_scope"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "channel_id"],
            ["notification_channel.organization_id", "notification_channel.id"],
            name=op.f("fk_notification_route_organization_id_channel_id_notification_channel"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            name=op.f("fk_notification_route_organization_id_monitor_id_monitor"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["project.organization_id", "project.id"],
            name=op.f("fk_notification_route_organization_id_project_id_project"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_route")),
        sa.UniqueConstraint(
            "organization_id", "id", name=op.f("uq_notification_route_organization_id_id")
        ),
    )
    op.create_index(
        "ix_notification_route_organization_id_channel_id",
        "notification_route",
        ["organization_id", "channel_id"],
        unique=False,
    )
    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=True),
        sa.Column("incident_event_id", sa.Uuid(), nullable=True),
        sa.Column("monitor_id", sa.Uuid(), nullable=True),
        sa.Column("channel_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("dedupe_key", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("cancel_reason", sa.Text(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_token", sa.Uuid(), nullable=True),
        sa.Column("last_result_code", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(state = 'CANCELLED') = (cancel_reason IS NOT NULL)",
            name=op.f("ck_notification_outbox_cancel_has_reason"),
        ),
        sa.CheckConstraint(
            EVENT_CHECK,
            name=op.f("ck_notification_outbox_event_type_valid"),
        ),
        sa.CheckConstraint(
            "state <> 'LEASED' OR (lease_until IS NOT NULL AND lease_token IS NOT NULL)",
            name=op.f("ck_notification_outbox_lease_consistent"),
        ),
        sa.CheckConstraint(
            "state IN ('PENDING', 'LEASED', 'SENT', 'FAILED', 'CANCELLED')",
            name=op.f("ck_notification_outbox_state_valid"),
        ),
        sa.CheckConstraint(
            "attempts BETWEEN 0 AND 8", name=op.f("ck_notification_outbox_attempts_range")
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "channel_id"],
            ["notification_channel.organization_id", "notification_channel.id"],
            name=op.f("fk_notification_outbox_organization_id_channel_id_notification_channel"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "incident_event_id"],
            ["incident_event.organization_id", "incident_event.id"],
            name=op.f("fk_notification_outbox_organization_id_incident_event_id_incident_event"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "incident_id"],
            ["incident.organization_id", "incident.id"],
            name=op.f("fk_notification_outbox_organization_id_incident_id_incident"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            name=op.f("fk_notification_outbox_organization_id_monitor_id_monitor"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_outbox")),
        sa.UniqueConstraint(
            "organization_id",
            "dedupe_key",
            name=op.f("uq_notification_outbox_organization_id_dedupe_key"),
        ),
        sa.UniqueConstraint(
            "organization_id", "id", name=op.f("uq_notification_outbox_organization_id_id")
        ),
    )
    op.create_index(
        "ix_notification_outbox_lease_until_leased",
        "notification_outbox",
        ["lease_until"],
        unique=False,
        postgresql_where=sa.text("state = 'LEASED'"),
    )
    op.create_index(
        "ix_notification_outbox_next_attempt_at_pending",
        "notification_outbox",
        ["next_attempt_at"],
        unique=False,
        postgresql_where=sa.text("state = 'PENDING'"),
    )
    op.create_index(
        "ix_notification_outbox_organization_id_channel_id_created_at",
        "notification_outbox",
        ["organization_id", "channel_id", "created_at"],
        unique=False,
    )
    op.create_table(
        "notification_delivery",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("outbox_id", sa.Uuid(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("recipient_user_id", sa.Uuid(), nullable=True),
        sa.Column("result_code", sa.Text(), nullable=False),
        sa.Column("provider_ref", sa.Text(), nullable=True),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "attempt BETWEEN 1 AND 8", name=op.f("ck_notification_delivery_attempt_range")
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "outbox_id"],
            ["notification_outbox.organization_id", "notification_outbox.id"],
            name=op.f("fk_notification_delivery_organization_id_outbox_id_notification_outbox"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["recipient_user_id"],
            ["app_user.id"],
            name=op.f("fk_notification_delivery_recipient_user_id_app_user"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_delivery")),
        sa.UniqueConstraint(
            "organization_id", "id", name=op.f("uq_notification_delivery_organization_id_id")
        ),
    )
    op.create_index(
        "ix_notification_delivery_attempted_at",
        "notification_delivery",
        ["attempted_at"],
        unique=False,
    )
    op.create_index(
        "ix_notification_delivery_organization_id_outbox_id",
        "notification_delivery",
        ["organization_id", "outbox_id"],
        unique=False,
    )
    for table, privileges in GRANTS.items():
        op.execute(f"GRANT {privileges} ON TABLE {table} TO {APP_ROLE}")


def downgrade() -> None:
    for table in GRANTS:
        op.execute(f"REVOKE ALL ON TABLE {table} FROM {APP_ROLE}")
    for table in reversed(list(GRANTS)):
        op.drop_table(table)
