"""Uptime, coverage, latency and incident reports (FR-UI-001/002/006, AC-013, IC-23).

Definitions (03_DATABASE_DESIGN.md §8):
- Only SCHEDULED results count; check-now (MANUAL) never does.
- Uptime = available (PASS + SLOW) / conclusive (PASS + SLOW + FAIL). Without conclusive samples
  uptime is unknown (null), never 100 %.
- Coverage = conclusive / expected slots, where expected slots = time the monitor existed within
  the window divided by its interval. BLOCKED, INCONCLUSIVE, paused time and missed slots are
  coverage gaps, never uptime.
- Estimated downtime = FAIL samples x interval (sampling estimate). Outage time = overlap of
  OUTAGE incidents (detection to recovery) with the window, also an estimate.
- Latency percentiles use available samples, nearest-rank (``percentile_disc``). They are exact
  while the window lies within raw retention (30 days); older windows combine hourly rollup
  percentiles and are labelled approximate.

Counts come from one hourly source per (monitor, hour): the rollup when one exists for an hour
fully inside the window, otherwise raw measurements. Uptime and latency therefore describe the
same scheduled samples. Every query is organization-scoped and bounded.
"""

import math
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.catalog.models import Monitor, MonitorLifecycle, Project
from sentinelops.errors import AppError
from sentinelops.measurements.rollups import raw_boundary

PERIODS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
MAX_CUSTOM_DAYS = 366

_HOURS = """
WITH r AS (
    SELECT monitor_id, window_start AS h, conclusive_samples AS c, available_samples AS a,
           failed_samples AS f, blocked_samples AS b, inconclusive_samples AS i,
           latency_p50_ms AS p50, latency_p95_ms AS p95, downtime_seconds_est AS d
    FROM hourly_monitor_rollup
    WHERE organization_id = :org AND monitor_id = ANY(CAST(:ids AS uuid[]))
      AND window_start >= :start AND window_start + interval '1 hour' <= :end
),
raw AS (
    SELECT m.monitor_id, date_trunc('hour', m.observed_at, 'UTC') AS h,
           count(*) FILTER (WHERE m.result IN ('PASS', 'SLOW', 'FAIL')) AS c,
           count(*) FILTER (WHERE m.result IN ('PASS', 'SLOW')) AS a,
           count(*) FILTER (WHERE m.result = 'FAIL') AS f,
           count(*) FILTER (WHERE m.result = 'BLOCKED') AS b,
           count(*) FILTER (WHERE m.result = 'INCONCLUSIVE') AS i,
           percentile_disc(0.5) WITHIN GROUP (ORDER BY m.elapsed_ms)
               FILTER (WHERE m.result IN ('PASS', 'SLOW') AND m.elapsed_ms IS NOT NULL) AS p50,
           percentile_disc(0.95) WITHIN GROUP (ORDER BY m.elapsed_ms)
               FILTER (WHERE m.result IN ('PASS', 'SLOW') AND m.elapsed_ms IS NOT NULL) AS p95,
           count(*) FILTER (WHERE m.result = 'FAIL') * mon.interval_seconds AS d
    FROM measurement m
    JOIN monitor mon ON mon.organization_id = m.organization_id AND mon.id = m.monitor_id
    WHERE m.organization_id = :org AND m.monitor_id = ANY(CAST(:ids AS uuid[]))
      AND m.trigger = 'SCHEDULED' AND m.observed_at >= :start AND m.observed_at < :end
      AND NOT EXISTS (SELECT 1 FROM r WHERE r.monitor_id = m.monitor_id
                      AND r.h = date_trunc('hour', m.observed_at, 'UTC'))
    GROUP BY m.monitor_id, date_trunc('hour', m.observed_at, 'UTC'), mon.interval_seconds
),
hours AS (SELECT * FROM r UNION ALL SELECT * FROM raw)
"""

_TOTALS = (
    _HOURS
    + """
SELECT monitor_id, sum(c)::int, sum(a)::int, sum(f)::int, sum(b)::int, sum(i)::int, sum(d)::int,
       percentile_disc(0.5) WITHIN GROUP (ORDER BY p50),
       percentile_disc(0.95) WITHIN GROUP (ORDER BY p95)
FROM hours GROUP BY monitor_id
"""
)

_ORG_APPROX_LATENCY = (
    _HOURS
    + """
SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY p50),
       percentile_disc(0.95) WITHIN GROUP (ORDER BY p95)
FROM hours
"""
)

_EXACT_LATENCY = """
SELECT {group} percentile_disc(0.5) WITHIN GROUP (ORDER BY elapsed_ms),
       percentile_disc(0.95) WITHIN GROUP (ORDER BY elapsed_ms)
FROM measurement
WHERE organization_id = :org AND monitor_id = ANY(CAST(:ids AS uuid[]))
  AND trigger = 'SCHEDULED' AND result IN ('PASS', 'SLOW') AND elapsed_ms IS NOT NULL
  AND observed_at >= :start AND observed_at < :end
{group_by}
"""

_SERIES_EXACT = """
SELECT date_trunc(:unit, observed_at, :tz) AS bucket,
       count(*) FILTER (WHERE result IN ('PASS', 'SLOW', 'FAIL'))::int,
       count(*) FILTER (WHERE result IN ('PASS', 'SLOW'))::int,
       percentile_disc(0.5) WITHIN GROUP (ORDER BY elapsed_ms)
           FILTER (WHERE result IN ('PASS', 'SLOW') AND elapsed_ms IS NOT NULL),
       percentile_disc(0.95) WITHIN GROUP (ORDER BY elapsed_ms)
           FILTER (WHERE result IN ('PASS', 'SLOW') AND elapsed_ms IS NOT NULL)
FROM measurement
WHERE organization_id = :org AND monitor_id = ANY(CAST(:ids AS uuid[]))
  AND trigger = 'SCHEDULED' AND observed_at >= :start AND observed_at < :end
GROUP BY 1 ORDER BY 1
"""

_SERIES_APPROX = (
    _HOURS
    + """
SELECT date_trunc(:unit, h, :tz) AS bucket, sum(c)::int, sum(a)::int,
       percentile_disc(0.5) WITHIN GROUP (ORDER BY p50),
       percentile_disc(0.95) WITHIN GROUP (ORDER BY p95)
FROM hours GROUP BY 1 ORDER BY 1
"""
)

_INCIDENTS = """
SELECT monitor_id,
       count(*) FILTER (WHERE opened_at >= :start AND opened_at < :end)::int AS opened,
       count(*) FILTER (WHERE opened_at >= :start AND opened_at < :end
                        AND type = 'OUTAGE')::int AS opened_outage,
       count(*) FILTER (WHERE opened_at >= :start AND opened_at < :end
                        AND type = 'TLS_EXPIRY')::int AS opened_tls,
       count(*) FILTER (WHERE resolved_at >= :start AND resolved_at < :end)::int AS resolved,
       COALESCE(sum(EXTRACT(EPOCH FROM
           LEAST(COALESCE(resolved_at, :end), :end) - GREATEST(opened_at, :start)))
           FILTER (WHERE type = 'OUTAGE'), 0)::int AS outage_seconds,
       sum(EXTRACT(EPOCH FROM resolved_at - opened_at))
           FILTER (WHERE resolved_at >= :start AND resolved_at < :end) AS resolution_total,
       sum(EXTRACT(EPOCH FROM acknowledged_at - opened_at))
           FILTER (WHERE acknowledged_at IS NOT NULL AND opened_at >= :start
                   AND opened_at < :end) AS ack_total,
       count(acknowledged_at) FILTER (WHERE opened_at >= :start AND opened_at < :end)::int
           AS acked
FROM incident
WHERE organization_id = :org AND monitor_id = ANY(CAST(:ids AS uuid[]))
  AND opened_at < :end AND (resolved_at IS NULL OR resolved_at >= :start)
GROUP BY monitor_id
"""

_MEDIAN_RESOLUTION = """
SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM resolved_at - opened_at))
FROM incident
WHERE organization_id = :org AND monitor_id = ANY(CAST(:ids AS uuid[]))
  AND resolved_at >= :start AND resolved_at < :end
"""


@dataclass(frozen=True)
class Window:
    start: datetime
    end: datetime
    period: str
    bucket: str  # "hour" or "day" (in the organization's timezone)
    timezone: str
    exact_latency: bool


def resolve_window(
    period: str, date_from: date | None, date_to: date | None, timezone: str, now: datetime
) -> Window:
    """Presets end now. Custom ranges are whole local days (DST-aware), capped at now."""
    tz = ZoneInfo(timezone)
    if period in PERIODS:  # (now - period, now]: a check observed at "now" is included
        end = now + timedelta(microseconds=1)
        start = end - PERIODS[period]
    elif period == "custom":
        if date_from is None or date_to is None or date_from > date_to:
            raise AppError(422, "INVALID_RANGE", "Choose a start date on or before the end date")
        if (date_to - date_from).days + 1 > MAX_CUSTOM_DAYS:
            raise AppError(422, "INVALID_RANGE", f"Ranges may span at most {MAX_CUSTOM_DAYS} days")
        start = datetime.combine(date_from, time(), tz).astimezone(UTC)
        end = min(
            datetime.combine(date_to + timedelta(days=1), time(), tz).astimezone(UTC),
            now + timedelta(microseconds=1),
        )
        if start >= now:
            raise AppError(422, "INVALID_RANGE", "The range must start in the past")
    else:
        raise AppError(422, "INVALID_PERIOD", "Use 24h, 7d, 30d or custom")
    bucket = "hour" if end - start <= timedelta(hours=48) else "day"
    return Window(start, end, period, bucket, timezone, start >= raw_boundary(now))


@dataclass
class Stats:
    conclusive: int = 0
    available: int = 0
    failed: int = 0
    blocked: int = 0
    inconclusive: int = 0
    expected: int = 0
    downtime_est_seconds: int = 0
    p50_ms: int | None = None
    p95_ms: int | None = None
    incidents_opened: int = 0
    outage_incidents_opened: int = 0
    tls_incidents_opened: int = 0
    incidents_resolved: int = 0
    outage_seconds: int = 0
    resolution_total: float = 0.0
    ack_total: float = 0.0
    acked: int = 0

    @property
    def uptime_pct(self) -> float | None:
        return round(100.0 * self.available / self.conclusive, 3) if self.conclusive else None

    @property
    def coverage_pct(self) -> float | None:
        if not self.expected:
            return None
        return round(min(100.0, 100.0 * self.conclusive / self.expected), 2)

    @property
    def missed(self) -> int:
        return max(0, self.expected - self.conclusive - self.blocked - self.inconclusive)

    @property
    def mean_resolution_seconds(self) -> int | None:
        if not self.incidents_resolved:
            return None
        return int(self.resolution_total / self.incidents_resolved)

    @property
    def mean_ack_seconds(self) -> int | None:
        return int(self.ack_total / self.acked) if self.acked else None

    def add(self, other: Stats) -> None:
        for name in (
            "conclusive",
            "available",
            "failed",
            "blocked",
            "inconclusive",
            "expected",
            "downtime_est_seconds",
            "incidents_opened",
            "outage_incidents_opened",
            "tls_incidents_opened",
            "incidents_resolved",
            "outage_seconds",
            "resolution_total",
            "ack_total",
            "acked",
        ):
            setattr(self, name, getattr(self, name) + getattr(other, name))


@dataclass(frozen=True)
class MonitorInfo:
    id: uuid.UUID
    name: str
    hostname: str
    project_id: uuid.UUID
    project_name: str
    lifecycle: str
    interval_seconds: int
    created_at: datetime


@dataclass(frozen=True)
class MonitorReport:
    monitor: MonitorInfo
    stats: Stats


@dataclass(frozen=True)
class Point:
    bucket_start: datetime
    conclusive: int
    available: int
    p50_ms: int | None
    p95_ms: int | None

    @property
    def uptime_pct(self) -> float | None:
        return round(100.0 * self.available / self.conclusive, 3) if self.conclusive else None


@dataclass
class Report:
    window: Window
    summary: Stats
    median_resolution_seconds: int | None
    monitors: list[MonitorReport] = field(default_factory=list[MonitorReport])
    total_monitors: int = 0
    series: list[Point] = field(default_factory=list[Point])


def expected_slots(info: MonitorInfo, window: Window) -> int:
    start = max(window.start, info.created_at)
    seconds = (window.end - start).total_seconds()
    return max(0, math.floor(seconds / info.interval_seconds))


async def select_monitors(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    project_id: uuid.UUID | None = None,
    monitor_id: uuid.UUID | None = None,
    include_archived: bool = False,
) -> list[MonitorInfo]:
    stmt = (
        select(
            Monitor.id,
            Monitor.name,
            Monitor.hostname,
            Monitor.project_id,
            Project.name,
            Monitor.lifecycle,
            Monitor.interval_seconds,
            Monitor.created_at,
        )
        .join(
            Project,
            (Project.organization_id == Monitor.organization_id)
            & (Project.id == Monitor.project_id),
        )
        .where(Monitor.organization_id == organization_id)
        .order_by(func.lower(Monitor.name), Monitor.id)
    )
    if not include_archived and monitor_id is None:
        stmt = stmt.where(Monitor.lifecycle != MonitorLifecycle.ARCHIVED)
    if project_id is not None:
        stmt = stmt.where(Monitor.project_id == project_id)
    if monitor_id is not None:
        stmt = stmt.where(Monitor.id == monitor_id)
    return [MonitorInfo(*row) for row in await db.execute(stmt)]


def _params(organization_id: uuid.UUID, ids: list[uuid.UUID], window: Window) -> dict[str, Any]:
    return {"org": organization_id, "ids": ids, "start": window.start, "end": window.end}


async def build_report(
    db: AsyncSession,
    organization_id: uuid.UUID,
    monitors: list[MonitorInfo],
    window: Window,
    *,
    limit: int | None = None,
    offset: int = 0,
    with_series: bool = True,
) -> Report:
    ids = [m.id for m in monitors]
    params = _params(organization_id, ids, window)
    per: dict[uuid.UUID, Stats] = {
        m.id: Stats(expected=expected_slots(m, window)) for m in monitors
    }
    if ids:
        for row in await db.execute(text(_TOTALS), params):
            stats = per[row[0]]
            (
                stats.conclusive,
                stats.available,
                stats.failed,
                stats.blocked,
                stats.inconclusive,
                stats.downtime_est_seconds,
            ) = row[1:7]
            stats.p50_ms, stats.p95_ms = row[7], row[8]
        if window.exact_latency:
            sql = _EXACT_LATENCY.format(group="monitor_id,", group_by="GROUP BY monitor_id")
            for monitor_id, p50, p95 in await db.execute(text(sql), params):
                per[monitor_id].p50_ms, per[monitor_id].p95_ms = p50, p95
        for row in await db.execute(text(_INCIDENTS), params):
            stats = per[row[0]]
            stats.incidents_opened = row.opened
            stats.outage_incidents_opened = row.opened_outage
            stats.tls_incidents_opened = row.opened_tls
            stats.incidents_resolved = row.resolved
            stats.outage_seconds = row.outage_seconds
            stats.resolution_total = float(row.resolution_total or 0)
            stats.ack_total = float(row.ack_total or 0)
            stats.acked = row.acked
    summary = Stats()
    for stats in per.values():
        summary.add(stats)
    median: int | None = None
    if ids:
        if window.exact_latency:
            sql = _EXACT_LATENCY.format(group="", group_by="")
            summary.p50_ms, summary.p95_ms = (await db.execute(text(sql), params)).one()
        else:
            summary.p50_ms, summary.p95_ms = (
                await db.execute(text(_ORG_APPROX_LATENCY), params)
            ).one()
        value = await db.scalar(text(_MEDIAN_RESOLUTION), params)
        median = int(value) if value is not None else None
    page = monitors[offset : offset + limit] if limit is not None else monitors
    report = Report(
        window,
        summary,
        median,
        [MonitorReport(m, per[m.id]) for m in page],
        len(monitors),
    )
    if with_series and ids:
        report.series = await series(db, organization_id, ids, window)
    return report


async def series(
    db: AsyncSession, organization_id: uuid.UUID, ids: list[uuid.UUID], window: Window
) -> list[Point]:
    sql = _SERIES_EXACT if window.exact_latency else _SERIES_APPROX
    params = {**_params(organization_id, ids, window), "unit": window.bucket, "tz": window.timezone}
    return [Point(*row) for row in await db.execute(text(sql), params)]
