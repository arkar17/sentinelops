"""Check results (03_DATABASE_DESIGN.md §2.4). Append-only; no body, header, query string or IP."""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from sentinelops.db.base import Base, new_id

RESULT_CHECK = "result IN ('PASS', 'SLOW', 'FAIL', 'BLOCKED', 'INCONCLUSIVE')"


class Measurement(Base):
    __tablename__ = "measurement"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        Index(
            "uq_measurement_monitor_id_job_id",
            "monitor_id",
            "job_id",
            unique=True,
            postgresql_where=text("job_id IS NOT NULL"),
        ),
        Index(
            "ix_measurement_organization_id_monitor_id_observed_at",
            "organization_id",
            "monitor_id",
            "observed_at",
        ),
        Index("ix_measurement_observed_at", "observed_at"),  # retention batches (G6)
        CheckConstraint(RESULT_CHECK, name="result_valid"),
        CheckConstraint("trigger IN ('SCHEDULED', 'MANUAL')", name="trigger_valid"),
        CheckConstraint("source_kind IN ('HTTP_PROBE', 'AGENT_METRIC')", name="source_kind_valid"),
        CheckConstraint("elapsed_ms IS NULL OR elapsed_ms >= 0", name="elapsed_nonnegative"),
        CheckConstraint("attempt_count BETWEEN 1 AND 3", name="attempt_count_range"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID]
    monitor_id: Mapped[uuid.UUID]
    job_id: Mapped[uuid.UUID | None]
    trigger: Mapped[str] = mapped_column(Text)
    source_kind: Mapped[str] = mapped_column(Text, default="HTTP_PROBE")
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    scheduled_for: Mapped[datetime | None]
    observed_at: Mapped[datetime]
    ingested_at: Mapped[datetime]
    result: Mapped[str] = mapped_column(Text)
    failure_category: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(Integer)
    elapsed_ms: Mapped[int | None] = mapped_column(Integer)
    attempt_count: Mapped[int] = mapped_column(Integer, default=1)
    tls_not_after: Mapped[datetime | None]
    value_numeric: Mapped[float | None] = mapped_column(Numeric)  # reserved for Phase 2


class HourlyMonitorRollup(Base):
    """Hourly aggregates of scheduled measurements (G6, ``measurements.rollups``); kept 12 months.

    Uptime = available / conclusive; missed_slots = expected slots in the hour (current interval)
    minus scheduled samples; latency percentiles over available (PASS/SLOW) samples;
    downtime_seconds_est = failed samples x interval (an estimate, not observed downtime)."""

    __tablename__ = "hourly_monitor_rollup"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        Index("ix_hourly_monitor_rollup_window_start", "window_start"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    monitor_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    window_start: Mapped[datetime] = mapped_column(primary_key=True)
    conclusive_samples: Mapped[int] = mapped_column(Integer, default=0)
    available_samples: Mapped[int] = mapped_column(Integer, default=0)
    failed_samples: Mapped[int] = mapped_column(Integer, default=0)
    blocked_samples: Mapped[int] = mapped_column(Integer, default=0)
    inconclusive_samples: Mapped[int] = mapped_column(Integer, default=0)
    missed_slots: Mapped[int] = mapped_column(Integer, default=0)
    latency_p50_ms: Mapped[int | None] = mapped_column(Integer)
    latency_p95_ms: Mapped[int | None] = mapped_column(Integer)
    downtime_seconds_est: Mapped[int] = mapped_column(Integer, default=0)
