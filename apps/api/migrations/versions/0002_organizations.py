"""G2 organizations, memberships and tenant isolation.

Tables: organization, organization_limit, organization_member, org_invitation, user_preference,
project. Adds the audit_event.organization_id → organization FK. Grants DML (no DELETE on
membership history) to the existing sentinelops_app role. No accounts or organizations are created.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-31
"""

import uuid
from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinelops_app"
ROLE_CHECK = "role IN ('ORG_OWNER', 'ORG_ADMIN', 'ORG_MEMBER', 'VIEWER')"

GRANTS = {
    "organization": "SELECT, INSERT, UPDATE",
    "organization_limit": "SELECT, INSERT, UPDATE",
    "organization_member": "SELECT, INSERT, UPDATE",
    "org_invitation": "SELECT, INSERT, UPDATE",
    "user_preference": "SELECT, INSERT, UPDATE, DELETE",
    "project": "SELECT, INSERT, UPDATE",
}


def _ts(name: str, nullable: bool = False) -> sa.Column[datetime]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(name: str, target: str, nullable: bool = True) -> sa.Column[uuid.UUID]:
    return sa.Column(name, sa.Uuid(), sa.ForeignKey(target, ondelete="RESTRICT"), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "organization",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("slug", sa.Text(), nullable=False, unique=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("timezone", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        _ts("suspended_at", nullable=True),
        sa.Column("suspended_reason", sa.Text(), nullable=True),
        _fk("created_by", "app_user.id", nullable=False),
        _ts("created_at"),
        _ts("updated_at"),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint("status IN ('ACTIVE', 'SUSPENDED')", name="status_valid"),
        sa.CheckConstraint(
            "status = 'ACTIVE' OR suspended_at IS NOT NULL", name="suspended_has_timestamp"
        ),
    )
    op.create_table(
        "organization_limit",
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("organization.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("max_monitors", sa.Integer(), nullable=True),
        sa.Column("min_interval_seconds", sa.Integer(), nullable=True),
        sa.Column("max_status_pages", sa.Integer(), nullable=True),
        sa.Column("max_channels", sa.Integer(), nullable=True),
        _fk("updated_by", "app_user.id"),
        _ts("updated_at"),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint("max_monitors BETWEEN 1 AND 10000", name="max_monitors_range"),
        sa.CheckConstraint("min_interval_seconds IN (60, 120, 300)", name="min_interval_allowed"),
        sa.CheckConstraint("max_status_pages BETWEEN 0 AND 100", name="max_status_pages_range"),
        sa.CheckConstraint("max_channels BETWEEN 0 AND 100", name="max_channels_range"),
    )
    op.create_table(
        "organization_member",
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("organization.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("app_user.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        _fk("invited_by", "app_user.id"),
        _ts("joined_at"),
        _ts("status_changed_at"),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(ROLE_CHECK, name="role_valid"),
        sa.CheckConstraint("status IN ('ACTIVE', 'SUSPENDED', 'REMOVED')", name="status_valid"),
    )
    op.create_index(
        "ix_organization_member_user_id_active",
        "organization_member",
        ["user_id"],
        postgresql_where=sa.text("status = 'ACTIVE'"),
    )
    op.create_table(
        "org_invitation",
        sa.Column("id", sa.Uuid(), primary_key=True),
        _fk("organization_id", "organization.id", nullable=False),
        sa.Column("email_normalized", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False, unique=True),
        _fk("invited_by", "app_user.id", nullable=False),
        sa.Column("invited_by_plane", sa.Text(), nullable=False),
        _ts("expires_at"),
        _ts("accepted_at", nullable=True),
        _fk("accepted_user_id", "app_user.id"),
        _ts("revoked_at", nullable=True),
        _ts("created_at"),
        sa.CheckConstraint(ROLE_CHECK, name="role_valid"),
        sa.CheckConstraint("invited_by_plane IN ('ORG', 'PLATFORM')", name="plane_valid"),
    )
    op.create_index(
        "uq_org_invitation_organization_id_email_pending",
        "org_invitation",
        ["organization_id", "email_normalized"],
        unique=True,
        postgresql_where=sa.text("accepted_at IS NULL AND revoked_at IS NULL"),
    )
    op.create_table(
        "user_preference",
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("app_user.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("selected_org_id", sa.Uuid(), nullable=True),
        _ts("updated_at"),
        # Composite FK: a preference can only point at the user's own membership.
        sa.ForeignKeyConstraint(
            ["selected_org_id", "user_id"],
            ["organization_member.organization_id", "organization_member.user_id"],
            ondelete="RESTRICT",
        ),
    )
    op.create_table(
        "project",
        sa.Column("id", sa.Uuid(), primary_key=True),
        _fk("organization_id", "organization.id", nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        _ts("archived_at", nullable=True),
        _fk("created_by", "app_user.id", nullable=False),
        _ts("created_at"),
        _ts("updated_at"),
        sa.Column("version", sa.Integer(), nullable=False),
        # Target for composite FKs from G3+ children, e.g. monitor(organization_id, project_id).
        sa.UniqueConstraint("organization_id", "id"),
    )
    op.create_index(
        "uq_project_organization_id_name_active",
        "project",
        ["organization_id", sa.text("lower(name)")],
        unique=True,
        postgresql_where=sa.text("archived_at IS NULL"),
    )
    op.create_foreign_key(
        "fk_audit_event_organization_id_organization",
        "audit_event",
        "organization",
        ["organization_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    for table, privileges in GRANTS.items():
        op.execute(f"GRANT {privileges} ON TABLE {table} TO {APP_ROLE}")


def downgrade() -> None:
    op.drop_constraint(
        "fk_audit_event_organization_id_organization", "audit_event", type_="foreignkey"
    )
    for table in GRANTS:
        op.execute(f"REVOKE ALL ON TABLE {table} FROM {APP_ROLE}")
    for table in (
        "project",
        "user_preference",
        "org_invitation",
        "organization_member",
        "organization_limit",
        "organization",
    ):
        op.drop_table(table)
