"""Hourly rollups and retention (NFR-006, OD-10, 03_DATABASE_DESIGN.md §8).

- Rollups aggregate SCHEDULED measurements per monitor and UTC hour. Upserts recompute the whole
  hour from raw rows, so they are idempotent and concurrent runs converge on the same values.
  Recent closed hours are recomputed on every run (late measurements arrive within a lease, far
  inside the recompute window).
- Retention keeps raw measurements 30 days and rollups 12 months. Before raw rows of an hour are
  deleted, that hour's rollup is written in the same transaction; deletes only touch hours that
  have a rollup (manual check-now results are never aggregated and simply expire). Deletes are
  batched. Incidents, audit and notification history are never deleted here.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

RAW_RETENTION = timedelta(days=30)
ROLLUP_RETENTION = timedelta(days=365)
RECOMPUTE_HOURS = 3
CLOSE_GRACE = timedelta(minutes=5)
DELETE_BATCH = 5000
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

_UPSERT = """
INSERT INTO hourly_monitor_rollup AS r (
    organization_id, monitor_id, window_start, conclusive_samples, available_samples,
    failed_samples, blocked_samples, inconclusive_samples, missed_slots, latency_p50_ms,
    latency_p95_ms, downtime_seconds_est)
SELECT m.organization_id, m.monitor_id, date_trunc('hour', m.observed_at, 'UTC'),
    count(*) FILTER (WHERE m.result IN ('PASS', 'SLOW', 'FAIL')),
    count(*) FILTER (WHERE m.result IN ('PASS', 'SLOW')),
    count(*) FILTER (WHERE m.result = 'FAIL'),
    count(*) FILTER (WHERE m.result = 'BLOCKED'),
    count(*) FILTER (WHERE m.result = 'INCONCLUSIVE'),
    GREATEST(0, 3600 / mon.interval_seconds - count(*)),
    percentile_disc(0.5) WITHIN GROUP (ORDER BY m.elapsed_ms)
        FILTER (WHERE m.result IN ('PASS', 'SLOW') AND m.elapsed_ms IS NOT NULL),
    percentile_disc(0.95) WITHIN GROUP (ORDER BY m.elapsed_ms)
        FILTER (WHERE m.result IN ('PASS', 'SLOW') AND m.elapsed_ms IS NOT NULL),
    count(*) FILTER (WHERE m.result = 'FAIL') * mon.interval_seconds
FROM measurement m
JOIN monitor mon ON mon.organization_id = m.organization_id AND mon.id = m.monitor_id
WHERE m.trigger = 'SCHEDULED' AND m.observed_at >= :start AND m.observed_at < :end
{missing_only}
GROUP BY m.organization_id, m.monitor_id, date_trunc('hour', m.observed_at, 'UTC'),
    mon.interval_seconds
ON CONFLICT (organization_id, monitor_id, window_start) DO UPDATE SET
    conclusive_samples = EXCLUDED.conclusive_samples,
    available_samples = EXCLUDED.available_samples,
    failed_samples = EXCLUDED.failed_samples,
    blocked_samples = EXCLUDED.blocked_samples,
    inconclusive_samples = EXCLUDED.inconclusive_samples,
    missed_slots = EXCLUDED.missed_slots,
    latency_p50_ms = EXCLUDED.latency_p50_ms,
    latency_p95_ms = EXCLUDED.latency_p95_ms,
    downtime_seconds_est = EXCLUDED.downtime_seconds_est
"""
_MISSING_ONLY = """
AND NOT EXISTS (
    SELECT 1 FROM hourly_monitor_rollup x
    WHERE x.organization_id = m.organization_id AND x.monitor_id = m.monitor_id
      AND x.window_start = date_trunc('hour', m.observed_at, 'UTC'))
"""

_DELETE_RAW = """
DELETE FROM measurement WHERE id IN (
    SELECT m.id FROM measurement m
    WHERE m.observed_at < :boundary
      AND (m.trigger = 'MANUAL' OR EXISTS (
          SELECT 1 FROM hourly_monitor_rollup r
          WHERE r.organization_id = m.organization_id AND r.monitor_id = m.monitor_id
            AND r.window_start = date_trunc('hour', m.observed_at, 'UTC')))
    LIMIT :batch)
"""
_DELETE_ROLLUPS = """
DELETE FROM hourly_monitor_rollup WHERE ctid IN (
    SELECT ctid FROM hourly_monitor_rollup WHERE window_start < :boundary LIMIT :batch)
"""


def hour_floor(value: datetime) -> datetime:
    return value.replace(minute=0, second=0, microsecond=0)


def raw_boundary(now: datetime) -> datetime:
    """Raw rows older than this hour boundary may be deleted (after their rollup exists)."""
    return hour_floor(now - RAW_RETENTION)


async def rollup_range(
    db: AsyncSession, start: datetime, end: datetime, *, missing_only: bool = False
) -> int:
    """Upsert rollups for whole UTC hours in [start, end). No commit."""
    sql = _UPSERT.format(missing_only=_MISSING_ONLY if missing_only else "")
    result = await db.execute(text(sql), {"start": start, "end": end})
    return int(getattr(result, "rowcount", 0) or 0)


async def rollup_recent(db: AsyncSession, now: datetime) -> int:
    """Recompute the last few closed hours (a closed hour ended at least CLOSE_GRACE ago)."""
    end = hour_floor(now - CLOSE_GRACE)
    return await rollup_range(db, end - timedelta(hours=RECOMPUTE_HOURS), end)


async def apply_retention(db: AsyncSession, now: datetime, *, batch: int = DELETE_BATCH) -> int:
    """Roll up every expiring hour that lacks a rollup, then delete one batch of expired raw
    rows and one batch of expired rollups. Returns raw rows deleted. No commit."""
    boundary = raw_boundary(now)
    await rollup_range(db, EPOCH, boundary, missing_only=True)
    deleted = await db.execute(text(_DELETE_RAW), {"boundary": boundary, "batch": batch})
    await db.execute(
        text(_DELETE_ROLLUPS), {"boundary": hour_floor(now - ROLLUP_RETENTION), "batch": batch}
    )
    return int(getattr(deleted, "rowcount", 0) or 0)
