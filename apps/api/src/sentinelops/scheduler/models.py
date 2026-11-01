"""Scheduler tables: worker heartbeats, monitor schedules and health counters."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from sentinelops.db.base import Base


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeat"
    __table_args__ = (CheckConstraint("kind IN ('WORKER', 'NOTIFIER')", name="kind_valid"),)

    worker_id: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    last_seen_at: Mapped[datetime]
    in_flight: Mapped[int] = mapped_column(Integer, default=0)
    version_label: Mapped[str | None] = mapped_column(Text)


class MonitorSchedule(Base):
    """Scheduling and lease state, one row per monitor (02_TECHNICAL_ARCHITECTURE.md §5)."""

    __tablename__ = "monitor_schedule"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        Index("ix_monitor_schedule_next_due_at", "next_due_at"),
        CheckConstraint("missed_slots >= 0", name="missed_slots_nonnegative"),
    )

    monitor_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID]
    next_due_at: Mapped[datetime]
    planned_due_at: Mapped[datetime | None]
    generation: Mapped[int] = mapped_column(Integer, default=1)
    lease_owner: Mapped[str | None] = mapped_column(Text)
    lease_until: Mapped[datetime | None]
    current_job_id: Mapped[uuid.UUID | None]
    current_trigger: Mapped[str | None] = mapped_column(Text)
    manual_check_requested_at: Mapped[datetime | None]
    last_manual_check_requested_at: Mapped[datetime | None]
    missed_slots: Mapped[int] = mapped_column(Integer, default=0)


class MonitorHealth(Base):
    """Health state and consecutive counters (one per monitor), maintained by the G4 state
    machine (``incidents.health``) from scheduled conclusive results only."""

    __tablename__ = "monitor_health"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        CheckConstraint("state IN ('UNKNOWN', 'UP', 'DEGRADED', 'DOWN')", name="state_valid"),
    )

    monitor_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID]
    state: Mapped[str] = mapped_column(Text, default="UNKNOWN")
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    consecutive_successes: Mapped[int] = mapped_column(Integer, default=0)
    consecutive_slow: Mapped[int] = mapped_column(Integer, default=0)
    consecutive_passes: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    consecutive_blocked: Mapped[int] = mapped_column(Integer, default=0)
    last_measurement_id: Mapped[uuid.UUID | None]
    last_conclusive_at: Mapped[datetime | None]
    last_change_at: Mapped[datetime | None]
    version: Mapped[int] = mapped_column(Integer, default=1)
