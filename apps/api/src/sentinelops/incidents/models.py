"""Incidents and their append-only event timeline (03_DATABASE_DESIGN.md §2.5).

Titles and event details are sanitized: no URL, query string, header, body or resolved IP.
``opened_measurement_id`` has no foreign key because raw measurements are retained 30 days and
incidents 12 months (NFR-006).
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from sentinelops import clock
from sentinelops.db.base import Base, new_id


class IncidentType:
    OUTAGE = "OUTAGE"
    TLS_EXPIRY = "TLS_EXPIRY"


class IncidentStatus:
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class Severity:
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"


class Resolution:
    AUTO = "AUTO"
    MANUAL = "MANUAL"


class EventType:
    OPENED = "OPENED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    ASSIGNED = "ASSIGNED"
    UNASSIGNED = "UNASSIGNED"
    COMMENTED = "COMMENTED"
    RESOLVED = "RESOLVED"


class Incident(Base):
    __tablename__ = "incident"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "assigned_user_id"],
            ["organization_member.organization_id", "organization_member.user_id"],
            ondelete="RESTRICT",
        ),
        CheckConstraint("type IN ('OUTAGE', 'TLS_EXPIRY')", name="type_valid"),
        CheckConstraint("source_kind IN ('HTTP_PROBE')", name="source_kind_valid"),
        CheckConstraint("severity IN ('CRITICAL', 'WARNING')", name="severity_valid"),
        CheckConstraint("status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')", name="status_valid"),
        CheckConstraint(
            "resolution IS NULL OR resolution IN ('AUTO', 'MANUAL')", name="resolution_valid"
        ),
        CheckConstraint(
            "(status = 'RESOLVED') = (resolved_at IS NOT NULL AND resolution IS NOT NULL)",
            name="resolved_consistent",
        ),
        CheckConstraint(
            "resolution IS DISTINCT FROM 'MANUAL' OR resolved_by IS NOT NULL",
            name="manual_resolution_has_actor",
        ),
        CheckConstraint(
            "status <> 'ACKNOWLEDGED' OR acknowledged_at IS NOT NULL",
            name="acknowledged_has_time",
        ),
        # At most one active incident per monitor and type (FR-INC-002).
        Index(
            "uq_incident_monitor_id_type_active",
            "monitor_id",
            "type",
            unique=True,
            postgresql_where=text("status <> 'RESOLVED'"),
        ),
        Index(
            "ix_incident_organization_id_status_opened_at", "organization_id", "status", "opened_at"
        ),
        Index(
            "ix_incident_organization_id_monitor_id_opened_at",
            "organization_id",
            "monitor_id",
            "opened_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID]
    monitor_id: Mapped[uuid.UUID]
    type: Mapped[str] = mapped_column(Text)
    source_kind: Mapped[str] = mapped_column(Text, default="HTTP_PROBE")
    severity: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default=IncidentStatus.OPEN)
    title_sanitized: Mapped[str] = mapped_column(Text)
    opened_measurement_id: Mapped[uuid.UUID | None]
    opened_at: Mapped[datetime]
    acknowledged_at: Mapped[datetime | None]
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    resolved_at: Mapped[datetime | None]
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    resolution: Mapped[str | None] = mapped_column(Text)
    assigned_user_id: Mapped[uuid.UUID | None]
    last_event_at: Mapped[datetime]
    version: Mapped[int] = mapped_column(Integer, default=1)


class IncidentEvent(Base):
    """Append-only timeline entry (UPDATE/DELETE are not granted to the app role)."""

    __tablename__ = "incident_event"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        ForeignKeyConstraint(
            ["organization_id", "incident_id"],
            ["incident.organization_id", "incident.id"],
            ondelete="RESTRICT",
        ),
        CheckConstraint("actor_kind IN ('USER', 'SYSTEM')", name="actor_kind_valid"),
        CheckConstraint(
            "actor_kind <> 'USER' OR actor_user_id IS NOT NULL", name="user_actor_has_id"
        ),
        CheckConstraint(
            "event_type IN ('OPENED', 'ACKNOWLEDGED', 'ASSIGNED', 'UNASSIGNED', 'COMMENTED', "
            "'RESOLVED')",
            name="event_type_valid",
        ),
        Index(
            "ix_incident_event_organization_id_incident_id_created_at",
            "organization_id",
            "incident_id",
            "created_at",
        ),
        # Each lifecycle transition happens at most once per incident (replay safety).
        Index(
            "uq_incident_event_incident_id_event_type_lifecycle",
            "incident_id",
            "event_type",
            unique=True,
            postgresql_where=text("event_type IN ('OPENED', 'ACKNOWLEDGED', 'RESOLVED')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID]
    incident_id: Mapped[uuid.UUID]
    actor_kind: Mapped[str] = mapped_column(Text)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    event_type: Mapped[str] = mapped_column(Text)
    details_sanitized_json: Mapped[dict[str, Any]]
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
