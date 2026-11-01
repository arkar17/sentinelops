"""Organization-plane tables (03_DATABASE_DESIGN.md §2.2).

Tenant rule: organization-owned rows carry organization_id, and references within a tenant use
composite foreign keys so rows can never point across organizations.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from sentinelops import clock
from sentinelops.db.base import Base, new_id


class OrgStatus:
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"


class OrgRole:
    OWNER = "ORG_OWNER"
    ADMIN = "ORG_ADMIN"
    MEMBER = "ORG_MEMBER"
    VIEWER = "VIEWER"

    ALL = frozenset({OWNER, ADMIN, MEMBER, VIEWER})


class MemberStatus:
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REMOVED = "REMOVED"


ROLE_CHECK = "role IN ('ORG_OWNER', 'ORG_ADMIN', 'ORG_MEMBER', 'VIEWER')"


class Organization(Base):
    __tablename__ = "organization"
    __table_args__ = (
        CheckConstraint("status IN ('ACTIVE', 'SUSPENDED')", name="status_valid"),
        CheckConstraint(
            "status = 'ACTIVE' OR suspended_at IS NOT NULL", name="suspended_has_timestamp"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(Text, unique=True)
    name: Mapped[str] = mapped_column(Text)
    timezone: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    suspended_at: Mapped[datetime | None]
    suspended_reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_user.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )
    version: Mapped[int] = mapped_column(Integer, default=1)


class OrganizationLimit(Base):
    """Per-organization overrides; NULL means the platform default applies."""

    __tablename__ = "organization_limit"
    __table_args__ = (
        CheckConstraint("max_monitors BETWEEN 1 AND 10000", name="max_monitors_range"),
        CheckConstraint("min_interval_seconds IN (60, 120, 300)", name="min_interval_allowed"),
        CheckConstraint("max_status_pages BETWEEN 0 AND 100", name="max_status_pages_range"),
        CheckConstraint("max_channels BETWEEN 0 AND 100", name="max_channels_range"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id", ondelete="RESTRICT"), primary_key=True
    )
    max_monitors: Mapped[int | None] = mapped_column(Integer)
    min_interval_seconds: Mapped[int | None] = mapped_column(Integer)
    max_status_pages: Mapped[int | None] = mapped_column(Integer)
    max_channels: Mapped[int | None] = mapped_column(Integer)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )
    version: Mapped[int] = mapped_column(Integer, default=1)


class OrganizationMember(Base):
    __tablename__ = "organization_member"
    __table_args__ = (
        CheckConstraint(ROLE_CHECK, name="role_valid"),
        CheckConstraint("status IN ('ACTIVE', 'SUSPENDED', 'REMOVED')", name="status_valid"),
        Index(
            "ix_organization_member_user_id_active",
            "user_id",
            postgresql_where=text("status = 'ACTIVE'"),
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id", ondelete="RESTRICT"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT"), primary_key=True
    )
    role: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    invited_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    joined_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    status_changed_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    version: Mapped[int] = mapped_column(Integer, default=1)


class OrgInvitation(Base):
    __tablename__ = "org_invitation"
    __table_args__ = (
        CheckConstraint(ROLE_CHECK, name="role_valid"),
        CheckConstraint("invited_by_plane IN ('ORG', 'PLATFORM')", name="plane_valid"),
        Index(
            "uq_org_invitation_organization_id_email_pending",
            "organization_id",
            "email_normalized",
            unique=True,
            postgresql_where=text("accepted_at IS NULL AND revoked_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id", ondelete="RESTRICT")
    )
    email_normalized: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    invited_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_user.id", ondelete="RESTRICT"))
    invited_by_plane: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime]
    accepted_at: Mapped[datetime | None]
    accepted_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    revoked_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)


class UserPreference(Base):
    """UI preference only; never consulted for authorization (ADR-004)."""

    __tablename__ = "user_preference"
    __table_args__ = (
        ForeignKeyConstraint(
            ["selected_org_id", "user_id"],
            ["organization_member.organization_id", "organization_member.user_id"],
            ondelete="RESTRICT",
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT"), primary_key=True
    )
    selected_org_id: Mapped[uuid.UUID | None]
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )
