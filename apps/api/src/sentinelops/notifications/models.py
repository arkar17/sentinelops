"""Notification channels, routes, outbox and delivery history (03_DATABASE_DESIGN.md §2.5).

Telegram credentials (bot token + chat ID) are sealed together in ``config_ciphertext`` and are
write-only. The outbox stores references, never rendered messages; delivery rows store result
codes only (no body, recipient address or secret).
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from sentinelops import clock
from sentinelops.db.base import Base, new_id


class ChannelType:
    TELEGRAM = "TELEGRAM"
    EMAIL = "EMAIL"


class NotifyEvent:
    INCIDENT_OPENED = "INCIDENT_OPENED"
    TLS_EXPIRY_WARNING = "TLS_EXPIRY_WARNING"
    INCIDENT_ACKNOWLEDGED = "INCIDENT_ACKNOWLEDGED"
    INCIDENT_RESOLVED = "INCIDENT_RESOLVED"
    MONITOR_AUTO_PAUSED = "MONITOR_AUTO_PAUSED"
    CHANNEL_TEST = "CHANNEL_TEST"

    ROUTABLE = (
        INCIDENT_OPENED,
        TLS_EXPIRY_WARNING,
        INCIDENT_ACKNOWLEDGED,
        INCIDENT_RESOLVED,
        MONITOR_AUTO_PAUSED,
    )


class OutboxState:
    PENDING = "PENDING"
    LEASED = "LEASED"
    SENT = "SENT"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


_EVENT_CHECK = (
    "event_type IN ('INCIDENT_OPENED', 'TLS_EXPIRY_WARNING', 'INCIDENT_ACKNOWLEDGED', "
    "'INCIDENT_RESOLVED', 'MONITOR_AUTO_PAUSED', 'CHANNEL_TEST')"
)


class NotificationChannel(Base):
    __tablename__ = "notification_channel"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        CheckConstraint("type IN ('TELEGRAM', 'EMAIL')", name="type_valid"),
        CheckConstraint(
            "(config_ciphertext IS NULL) = (config_key_id IS NULL)", name="config_consistent"
        ),
        CheckConstraint(
            "(type = 'TELEGRAM') = (config_ciphertext IS NOT NULL)", name="telegram_has_config"
        ),
        Index("ix_notification_channel_organization_id", "organization_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id", ondelete="RESTRICT")
    )
    type: Mapped[str] = mapped_column(Text)
    label: Mapped[str] = mapped_column(Text)
    config_ciphertext: Mapped[str | None] = mapped_column(Text)
    config_key_id: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_user.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )
    version: Mapped[int] = mapped_column(Integer, default=1)


class NotificationChannelRecipient(Base):
    """Email recipients: ACTIVE members of the channel's organization (OD-08)."""

    __tablename__ = "notification_channel_recipient"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "channel_id"],
            ["notification_channel.organization_id", "notification_channel.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["organization_member.organization_id", "organization_member.user_id"],
            ondelete="RESTRICT",
        ),
    )

    channel_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID]


class NotificationRoute(Base):
    """Which events go to which channel, for the whole organization, a project or a monitor."""

    __tablename__ = "notification_route"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        ForeignKeyConstraint(
            ["organization_id", "channel_id"],
            ["notification_channel.organization_id", "notification_channel.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["project.organization_id", "project.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "NOT (project_id IS NOT NULL AND monitor_id IS NOT NULL)", name="single_scope"
        ),
        CheckConstraint(
            "jsonb_typeof(event_types_json) = 'array' AND jsonb_array_length(event_types_json) > 0",
            name="event_types_nonempty",
        ),
        Index("ix_notification_route_organization_id_channel_id", "organization_id", "channel_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID]
    channel_id: Mapped[uuid.UUID]
    project_id: Mapped[uuid.UUID | None]
    monitor_id: Mapped[uuid.UUID | None]
    event_types_json: Mapped[list[str]] = mapped_column(JSONB)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    version: Mapped[int] = mapped_column(Integer, default=1)


class NotificationOutbox(Base):
    __tablename__ = "notification_outbox"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        UniqueConstraint("organization_id", "dedupe_key"),
        ForeignKeyConstraint(
            ["organization_id", "channel_id"],
            ["notification_channel.organization_id", "notification_channel.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "incident_id"],
            ["incident.organization_id", "incident.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "incident_event_id"],
            ["incident_event.organization_id", "incident_event.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        CheckConstraint(_EVENT_CHECK, name="event_type_valid"),
        CheckConstraint(
            "state IN ('PENDING', 'LEASED', 'SENT', 'FAILED', 'CANCELLED')", name="state_valid"
        ),
        CheckConstraint(
            "(state = 'CANCELLED') = (cancel_reason IS NOT NULL)", name="cancel_has_reason"
        ),
        CheckConstraint("attempts BETWEEN 0 AND 8", name="attempts_range"),
        CheckConstraint(
            "state <> 'LEASED' OR (lease_until IS NOT NULL AND lease_token IS NOT NULL)",
            name="lease_consistent",
        ),
        Index(
            "ix_notification_outbox_next_attempt_at_pending",
            "next_attempt_at",
            postgresql_where=text("state = 'PENDING'"),
        ),
        Index(
            "ix_notification_outbox_lease_until_leased",
            "lease_until",
            postgresql_where=text("state = 'LEASED'"),
        ),
        Index(
            "ix_notification_outbox_organization_id_channel_id_created_at",
            "organization_id",
            "channel_id",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID]
    incident_id: Mapped[uuid.UUID | None]
    incident_event_id: Mapped[uuid.UUID | None]
    monitor_id: Mapped[uuid.UUID | None]
    channel_id: Mapped[uuid.UUID]
    event_type: Mapped[str] = mapped_column(Text)
    dedupe_key: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text, default=OutboxState.PENDING)
    cancel_reason: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime]
    lease_until: Mapped[datetime | None]
    lease_token: Mapped[uuid.UUID | None]
    last_result_code: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    sent_at: Mapped[datetime | None]


class NotificationDelivery(Base):
    """One provider attempt (per email recipient). Result codes only."""

    __tablename__ = "notification_delivery"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        ForeignKeyConstraint(
            ["organization_id", "outbox_id"],
            ["notification_outbox.organization_id", "notification_outbox.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(["recipient_user_id"], ["app_user.id"], ondelete="RESTRICT"),
        CheckConstraint("attempt BETWEEN 1 AND 8", name="attempt_range"),
        Index("ix_notification_delivery_organization_id_outbox_id", "organization_id", "outbox_id"),
        Index("ix_notification_delivery_attempted_at", "attempted_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID]
    outbox_id: Mapped[uuid.UUID]
    attempt: Mapped[int] = mapped_column(Integer)
    recipient_user_id: Mapped[uuid.UUID | None]
    result_code: Mapped[str] = mapped_column(Text)
    provider_ref: Mapped[str | None] = mapped_column(Text)
    attempted_at: Mapped[datetime]
