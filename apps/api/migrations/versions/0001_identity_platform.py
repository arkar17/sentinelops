"""G1 identity and platform plane.

Tables: app_user, session, auth_token, auth_throttle, platform_admin, platform_admin_invitation,
platform_settings, audit_event, worker_heartbeat. Creates the NOLOGIN group role sentinelops_app
with DML-only grants (audit_event: SELECT/INSERT only). No users or credentials are created.

Revision ID: 0001
Revises:
Create Date: 2026-10-31
"""

import uuid
from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinelops_app"

# ADR-017 defaults; status pages and channels are not fixed by the baseline (G1 choice).
PLATFORM_SETTINGS_DEFAULTS = {
    "default_max_monitors": 20,
    "min_interval_seconds": 60,
    "max_timeout_ms": 15000,
    "max_retry_attempts": 2,
    "max_custom_headers": 5,
    "validation_max_bytes": 65536,
    "check_now_per_monitor_seconds": 60,
    "check_now_per_org_hour": 30,
    "default_max_status_pages": 3,
    "default_max_channels": 10,
}

GRANTS = {
    "app_user": "SELECT, INSERT, UPDATE",
    "session": "SELECT, INSERT, UPDATE, DELETE",
    "auth_token": "SELECT, INSERT, UPDATE, DELETE",
    "auth_throttle": "SELECT, INSERT, UPDATE, DELETE",
    "platform_admin": "SELECT, INSERT, UPDATE",
    "platform_admin_invitation": "SELECT, INSERT, UPDATE",
    "platform_settings": "SELECT, UPDATE",
    "audit_event": "SELECT, INSERT",
    "worker_heartbeat": "SELECT, INSERT, UPDATE, DELETE",
}


def _ts(name: str, nullable: bool = False) -> sa.Column[datetime]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _user_fk(name: str, nullable: bool = True) -> sa.Column[uuid.UUID]:
    return sa.Column(
        name, sa.Uuid(), sa.ForeignKey("app_user.id", ondelete="RESTRICT"), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "app_user",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("email_normalized", sa.Text(), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        _ts("email_verified_at", nullable=True),
        _ts("last_login_at", nullable=True),
        sa.Column("timezone", sa.Text(), nullable=False),
        _ts("created_at"),
        _ts("updated_at"),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "status IN ('PENDING_ACTIVATION', 'ACTIVE', 'DISABLED')", name="status_valid"
        ),
        sa.CheckConstraint(
            "password_hash IS NOT NULL OR status = 'PENDING_ACTIVATION'",
            name="password_required_unless_pending",
        ),
    )
    op.create_table(
        "session",
        sa.Column("id", sa.Uuid(), primary_key=True),
        _user_fk("user_id", nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False, unique=True),
        sa.Column("csrf_secret_hash", sa.Text(), nullable=False),
        _ts("created_at"),
        _ts("last_seen_at"),
        _ts("expires_at"),
        _ts("revoked_at", nullable=True),
        sa.Column("ip_hash", sa.Text(), nullable=True),
        sa.Column("user_agent_hash", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_session_user_id_active",
        "session",
        ["user_id"],
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.create_table(
        "auth_token",
        sa.Column("id", sa.Uuid(), primary_key=True),
        _user_fk("user_id", nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False, unique=True),
        _ts("expires_at"),
        _ts("used_at", nullable=True),
        _user_fk("created_by"),
        _ts("created_at"),
        sa.CheckConstraint("purpose IN ('ACTIVATION', 'PASSWORD_RESET')", name="purpose_valid"),
    )
    op.create_index(
        "ix_auth_token_user_id_purpose_unused",
        "auth_token",
        ["user_id", "purpose"],
        postgresql_where=sa.text("used_at IS NULL"),
    )
    op.create_table(
        "auth_throttle",
        sa.Column("scope", sa.Text(), primary_key=True),
        sa.Column("key_hash", sa.Text(), primary_key=True),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        _ts("window_started_at"),
        _ts("locked_until", nullable=True),
        _ts("updated_at"),
        sa.CheckConstraint("scope IN ('ACCOUNT', 'IP')", name="scope_valid"),
    )
    op.create_table(
        "platform_admin",
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("app_user.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("status", sa.Text(), nullable=False),
        _user_fk("granted_by"),
        _ts("granted_at"),
        _user_fk("deactivated_by"),
        _ts("deactivated_at", nullable=True),
        _ts("created_at"),
        _ts("updated_at"),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint("status IN ('ACTIVE', 'DEACTIVATED')", name="status_valid"),
    )
    op.create_table(
        "platform_admin_invitation",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email_normalized", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False, unique=True),
        _user_fk("invited_by", nullable=False),
        _ts("expires_at"),
        _ts("accepted_at", nullable=True),
        _user_fk("accepted_user_id"),
        _ts("revoked_at", nullable=True),
        _ts("created_at"),
    )
    op.create_index(
        "uq_platform_admin_invitation_email_pending",
        "platform_admin_invitation",
        ["email_normalized"],
        unique=True,
        postgresql_where=sa.text("accepted_at IS NULL AND revoked_at IS NULL"),
    )
    op.create_table(
        "platform_settings",
        sa.Column("id", sa.SmallInteger(), primary_key=True),
        *(sa.Column(name, sa.Integer(), nullable=False) for name in PLATFORM_SETTINGS_DEFAULTS),
        _user_fk("updated_by"),
        _ts("updated_at"),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint("id = 1", name="single_row"),
        sa.CheckConstraint("default_max_monitors BETWEEN 1 AND 10000", name="max_monitors_range"),
        sa.CheckConstraint("min_interval_seconds IN (60, 120, 300)", name="min_interval_allowed"),
        sa.CheckConstraint("max_timeout_ms BETWEEN 3000 AND 15000", name="max_timeout_range"),
        sa.CheckConstraint("max_retry_attempts BETWEEN 0 AND 2", name="max_retry_range"),
        sa.CheckConstraint("max_custom_headers BETWEEN 0 AND 5", name="max_headers_range"),
        sa.CheckConstraint(
            "validation_max_bytes BETWEEN 1024 AND 1048576", name="validation_bytes_range"
        ),
        sa.CheckConstraint(
            "check_now_per_monitor_seconds BETWEEN 10 AND 3600", name="check_now_monitor_range"
        ),
        sa.CheckConstraint("check_now_per_org_hour BETWEEN 0 AND 1000", name="check_now_org_range"),
        sa.CheckConstraint(
            "default_max_status_pages BETWEEN 0 AND 100", name="max_status_pages_range"
        ),
        sa.CheckConstraint("default_max_channels BETWEEN 0 AND 100", name="max_channels_range"),
    )
    # Configuration defaults, not a seed: no accounts or credentials.
    columns = ", ".join(PLATFORM_SETTINGS_DEFAULTS)
    values = ", ".join(str(v) for v in PLATFORM_SETTINGS_DEFAULTS.values())
    op.execute(
        f"INSERT INTO platform_settings (id, {columns}, updated_at, version) "
        f"VALUES (1, {values}, now(), 1)"
    )
    op.create_table(
        "audit_event",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("actor_kind", sa.Text(), nullable=False),
        _user_fk("actor_user_id"),
        sa.Column("actor_plane", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("entity_kind", sa.Text(), nullable=True),
        sa.Column("entity_id", sa.Uuid(), nullable=True),
        sa.Column("safe_diff_json", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.Text(), nullable=True),
        _ts("at"),
        sa.CheckConstraint("scope IN ('PLATFORM', 'ORGANIZATION')", name="scope_valid"),
        sa.CheckConstraint("actor_kind IN ('USER', 'SYSTEM', 'CLI')", name="actor_kind_valid"),
        sa.CheckConstraint("actor_plane IN ('PLATFORM', 'ORG', 'NONE')", name="actor_plane_valid"),
        sa.CheckConstraint(
            "scope <> 'ORGANIZATION' OR organization_id IS NOT NULL",
            name="organization_scope_has_org",
        ),
    )
    op.create_index("ix_audit_event_organization_id_at", "audit_event", ["organization_id", "at"])
    op.create_index("ix_audit_event_scope_at", "audit_event", ["scope", "at"])
    op.create_table(
        "worker_heartbeat",
        sa.Column("worker_id", sa.Text(), primary_key=True),
        sa.Column("kind", sa.Text(), nullable=False),
        _ts("last_seen_at"),
        sa.Column("in_flight", sa.Integer(), nullable=False),
        sa.Column("version_label", sa.Text(), nullable=True),
        sa.CheckConstraint("kind IN ('WORKER', 'NOTIFIER')", name="kind_valid"),
    )

    # Least-privilege runtime role (03_DATABASE_DESIGN.md §1). NOLOGIN group role: deployments
    # grant it to a login user they create themselves; no password is ever set here.
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                CREATE ROLE {APP_ROLE} NOLOGIN;
            END IF;
        END
        $$
        """
    )
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")
    for table, privileges in GRANTS.items():
        op.execute(f"GRANT {privileges} ON TABLE {table} TO {APP_ROLE}")


def downgrade() -> None:
    # The role is cluster-wide and may serve other databases, so it is left in place.
    for table in GRANTS:
        op.execute(f"REVOKE ALL ON TABLE {table} FROM {APP_ROLE}")
    for table in (
        "worker_heartbeat",
        "audit_event",
        "platform_settings",
        "platform_admin_invitation",
        "platform_admin",
        "auth_throttle",
        "auth_token",
        "session",
        "app_user",
    ):
        op.drop_table(table)
