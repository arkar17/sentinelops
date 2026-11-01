"""G7 SYSTEM_ADMIN MFA (OD-01): TOTP enrolment, hashed recovery codes and the session MFA gate.

The TOTP secret is stored only as AES-GCM ciphertext (MFA key ring); recovery codes only as
SHA-256 hashes. Sessions gain ``mfa_pending`` (VERIFY/ENROLL) and a failure counter. No rows are
created or changed.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinelops_app"
GRANTS = {
    "platform_admin_mfa": "SELECT, INSERT, UPDATE, DELETE",
    "platform_admin_recovery_code": "SELECT, INSERT, UPDATE, DELETE",
}


def upgrade() -> None:
    op.create_table(
        "platform_admin_mfa",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("secret_ciphertext", sa.Text(), nullable=False),
        sa.Column("secret_key_id", sa.Text(), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_step", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["app_user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.create_table(
        "platform_admin_recovery_code",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.Text(), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["app_user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code_hash"),
    )
    op.create_index(
        "ix_platform_admin_recovery_code_user_id_unused",
        "platform_admin_recovery_code",
        ["user_id"],
        postgresql_where=sa.text("used_at IS NULL"),
    )
    op.add_column("session", sa.Column("mfa_pending", sa.Text(), nullable=True))
    op.add_column(
        "session", sa.Column("mfa_failures", sa.Integer(), server_default="0", nullable=False)
    )
    op.create_check_constraint(
        "mfa_pending_valid", "session", "mfa_pending IS NULL OR mfa_pending IN ('VERIFY', 'ENROLL')"
    )
    for table, privileges in GRANTS.items():
        op.execute(f"GRANT {privileges} ON TABLE {table} TO {APP_ROLE}")


def downgrade() -> None:
    for table in GRANTS:
        op.execute(f"REVOKE ALL ON TABLE {table} FROM {APP_ROLE}")
    op.drop_constraint("mfa_pending_valid", "session", type_="check")
    op.drop_column("session", "mfa_failures")
    op.drop_column("session", "mfa_pending")
    op.drop_table("platform_admin_recovery_code")
    op.drop_table("platform_admin_mfa")
