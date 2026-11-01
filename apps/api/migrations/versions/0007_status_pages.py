"""G5 public status pages: page, selected monitors with public names, sanitized snapshot.

Pages are unpublished by default; the public endpoint reads only status_page_snapshot. The
platform read views planned for this revision belong to the G6 platform dashboard.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinelops_app"
GRANTS = {
    "status_page": "SELECT, INSERT, UPDATE",
    "status_page_monitor": "SELECT, INSERT, UPDATE, DELETE",
    "status_page_snapshot": "SELECT, INSERT, UPDATE",
}


def upgrade() -> None:
    op.create_table(
        "status_page",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("public_slug", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "public_slug ~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$'",
            name=op.f("ck_status_page_slug_format"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["app_user.id"],
            name=op.f("fk_status_page_created_by_app_user"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organization.id"],
            name=op.f("fk_status_page_organization_id_organization"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_status_page")),
        sa.UniqueConstraint(
            "organization_id", "id", name=op.f("uq_status_page_organization_id_id")
        ),
        sa.UniqueConstraint("public_slug", name=op.f("uq_status_page_public_slug")),
    )
    op.create_table(
        "status_page_snapshot",
        sa.Column("status_page_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("safe_payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "status_page_id"],
            ["status_page.organization_id", "status_page.id"],
            name=op.f("fk_status_page_snapshot_organization_id_status_page_id_status_page"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("status_page_id", name=op.f("pk_status_page_snapshot")),
    )
    op.create_table(
        "status_page_monitor",
        sa.Column("status_page_id", sa.Uuid(), nullable=False),
        sa.Column("monitor_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("public_display_name", sa.Text(), nullable=False),
        sa.Column("sort_order", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "sort_order BETWEEN 0 AND 1000", name=op.f("ck_status_page_monitor_sort_order_range")
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            name=op.f("fk_status_page_monitor_organization_id_monitor_id_monitor"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "status_page_id"],
            ["status_page.organization_id", "status_page.id"],
            name=op.f("fk_status_page_monitor_organization_id_status_page_id_status_page"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "status_page_id", "monitor_id", name=op.f("pk_status_page_monitor")
        ),
    )
    for table, privileges in GRANTS.items():
        op.execute(f"GRANT {privileges} ON TABLE {table} TO {APP_ROLE}")


def downgrade() -> None:
    for table in GRANTS:
        op.execute(f"REVOKE ALL ON TABLE {table} FROM {APP_ROLE}")
    for table in reversed(list(GRANTS)):
        op.drop_table(table)
