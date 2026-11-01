"""Platform-plane tables (03_DATABASE_DESIGN.md §2.1). SYSTEM_ADMIN is not an organization role."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, SmallInteger, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from sentinelops import clock
from sentinelops.db.base import Base, new_id


class PlatformAdminStatus:
    ACTIVE = "ACTIVE"
    DEACTIVATED = "DEACTIVATED"


class PlatformAdmin(Base):
    __tablename__ = "platform_admin"
    __table_args__ = (CheckConstraint("status IN ('ACTIVE', 'DEACTIVATED')", name="status_valid"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT"), primary_key=True
    )
    status: Mapped[str] = mapped_column(Text)
    # NULL only for the bootstrap admin.
    granted_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    granted_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    deactivated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    deactivated_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )
    version: Mapped[int] = mapped_column(Integer, default=1)


class PlatformAdminInvitation(Base):
    __tablename__ = "platform_admin_invitation"
    __table_args__ = (
        Index(
            "uq_platform_admin_invitation_email_pending",
            "email_normalized",
            unique=True,
            postgresql_where=text("accepted_at IS NULL AND revoked_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    email_normalized: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    invited_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_user.id", ondelete="RESTRICT"))
    expires_at: Mapped[datetime]
    accepted_at: Mapped[datetime | None]
    accepted_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    revoked_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)


class PlatformSettings(Base):
    """Single-row platform limits (FR-PLT-008). SSRF policy is deliberately not a setting."""

    __tablename__ = "platform_settings"
    __table_args__ = (
        CheckConstraint("id = 1", name="single_row"),
        CheckConstraint("default_max_monitors BETWEEN 1 AND 10000", name="max_monitors_range"),
        CheckConstraint("min_interval_seconds IN (60, 120, 300)", name="min_interval_allowed"),
        CheckConstraint("max_timeout_ms BETWEEN 3000 AND 15000", name="max_timeout_range"),
        CheckConstraint("max_retry_attempts BETWEEN 0 AND 2", name="max_retry_range"),
        CheckConstraint("max_custom_headers BETWEEN 0 AND 5", name="max_headers_range"),
        CheckConstraint(
            "validation_max_bytes BETWEEN 1024 AND 1048576", name="validation_bytes_range"
        ),
        CheckConstraint(
            "check_now_per_monitor_seconds BETWEEN 10 AND 3600", name="check_now_monitor_range"
        ),
        CheckConstraint("check_now_per_org_hour BETWEEN 0 AND 1000", name="check_now_org_range"),
        CheckConstraint(
            "default_max_status_pages BETWEEN 0 AND 100", name="max_status_pages_range"
        ),
        CheckConstraint("default_max_channels BETWEEN 0 AND 100", name="max_channels_range"),
    )

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    default_max_monitors: Mapped[int] = mapped_column(Integer)
    min_interval_seconds: Mapped[int] = mapped_column(Integer)
    max_timeout_ms: Mapped[int] = mapped_column(Integer)
    max_retry_attempts: Mapped[int] = mapped_column(Integer)
    max_custom_headers: Mapped[int] = mapped_column(Integer)
    validation_max_bytes: Mapped[int] = mapped_column(Integer)
    check_now_per_monitor_seconds: Mapped[int] = mapped_column(Integer)
    check_now_per_org_hour: Mapped[int] = mapped_column(Integer)
    default_max_status_pages: Mapped[int] = mapped_column(Integer)
    default_max_channels: Mapped[int] = mapped_column(Integer)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )
    version: Mapped[int] = mapped_column(Integer, default=1)
