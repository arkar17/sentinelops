"""Claim and complete check jobs (FR-SCH-001..003, 02_TECHNICAL_ARCHITECTURE.md §5).

Claim: ``FOR UPDATE SKIP LOCKED`` over due schedules of ACTIVE monitors in ACTIVE organizations;
each claimed row gets a lease covering the worst-case check duration and a fresh job id, then the
transaction commits before any network I/O. Complete: one transaction that verifies the job is
still current (job id + generation), inserts the measurement idempotently, applies the health
and incident state machine to scheduled conclusive results (``incidents.engine``), and advances
the schedule.
"""

import math
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.audit.service import AuditAction, record
from sentinelops.catalog.eligibility import DOMAIN_UNVERIFIED, POLICY_BLOCKED, covering_domain
from sentinelops.catalog.models import Monitor, MonitorLifecycle
from sentinelops.db.base import new_id
from sentinelops.incidents.engine import Observation, evaluate
from sentinelops.measurements.models import Measurement
from sentinelops.notifications.outbox import enqueue_auto_paused
from sentinelops.probes.http.engine import CheckOutcome, Result, lease_seconds
from sentinelops.realtime.publish import publish
from sentinelops.scheduler.models import MonitorHealth, MonitorSchedule
from sentinelops.tenancy.models import Organization, OrgStatus

SCHEDULED = "SCHEDULED"
MANUAL = "MANUAL"
AUTO_PAUSE_AFTER_BLOCKED = 3  # FR-MON-012


@dataclass(frozen=True)
class ClaimedJob:
    job_id: uuid.UUID
    monitor_id: uuid.UUID
    organization_id: uuid.UUID
    generation: int
    trigger: str
    scheduled_for: datetime
    hostname: str
    lease_until: datetime


@dataclass
class Capacity:
    """In-flight work of this worker, used to cap per-organization and per-host concurrency."""

    slots: int
    org_cap: int
    host_cap: int
    by_org: Counter[uuid.UUID]
    by_host: Counter[str]

    def admits(self, organization_id: uuid.UUID, hostname: str) -> bool:
        return (
            self.slots > 0
            and self.by_org[organization_id] < self.org_cap
            and self.by_host[hostname] < self.host_cap
        )

    def take(self, organization_id: uuid.UUID, hostname: str) -> None:
        self.slots -= 1
        self.by_org[organization_id] += 1
        self.by_host[hostname] += 1


async def claim_jobs(
    db: AsyncSession, *, worker_id: str, capacity: Capacity, now: datetime, batch: int
) -> list[ClaimedJob]:
    if capacity.slots <= 0:
        return []
    rows = list(
        await db.execute(
            select(MonitorSchedule, Monitor)
            .join(
                Monitor,
                (Monitor.organization_id == MonitorSchedule.organization_id)
                & (Monitor.id == MonitorSchedule.monitor_id),
            )
            .join(Organization, Organization.id == MonitorSchedule.organization_id)
            .where(
                Organization.status == OrgStatus.ACTIVE,
                Monitor.lifecycle == MonitorLifecycle.ACTIVE,
                (MonitorSchedule.next_due_at <= now)
                | MonitorSchedule.manual_check_requested_at.is_not(None),
                MonitorSchedule.lease_until.is_(None) | (MonitorSchedule.lease_until < now),
            )
            .order_by(MonitorSchedule.next_due_at)
            .limit(batch)
            .with_for_update(of=MonitorSchedule, skip_locked=True)
        )
    )
    claimed: list[ClaimedJob] = []
    for schedule, monitor in rows:
        if not capacity.admits(monitor.organization_id, monitor.hostname):
            continue  # stays unleased; the row lock is released at commit
        # Eligibility is re-validated before every check (FR-MON-003).
        if await covering_domain(db, monitor.organization_id, monitor.hostname, now) is None:
            monitor.lifecycle = MonitorLifecycle.DRAFT
            monitor.attention_reason = DOMAIN_UNVERIFIED
            monitor.version += 1
            schedule.generation += 1
            schedule.manual_check_requested_at = None
            continue
        trigger = SCHEDULED if schedule.next_due_at <= now else MANUAL
        lease_until = now + timedelta(
            seconds=lease_seconds(monitor.timeout_ms, monitor.retry_attempts)
        )
        job_id = new_id()
        schedule.lease_owner = worker_id
        schedule.lease_until = lease_until
        schedule.current_job_id = job_id
        schedule.current_trigger = trigger
        capacity.take(monitor.organization_id, monitor.hostname)
        claimed.append(
            ClaimedJob(
                job_id=job_id,
                monitor_id=monitor.id,
                organization_id=monitor.organization_id,
                generation=schedule.generation,
                trigger=trigger,
                scheduled_for=schedule.next_due_at
                if trigger == SCHEDULED
                else (schedule.manual_check_requested_at or now),
                hostname=monitor.hostname,
                lease_until=lease_until,
            )
        )
    await db.commit()
    return claimed


def next_slot(planned: datetime, interval_seconds: int, now: datetime) -> tuple[datetime, int]:
    """Fixed cadence: planned + interval; if that is already past, skip to the next future slot
    and report how many slots were missed (FR-SCH-002)."""
    interval = timedelta(seconds=interval_seconds)
    following = planned + interval
    if following > now:
        return following, 0
    missed = math.floor((now - following) / interval) + 1
    return following + missed * interval, missed


async def complete_job(
    db: AsyncSession,
    job: ClaimedJob,
    outcome: CheckOutcome,
    *,
    observed_at: datetime,
    now: datetime,
) -> str:
    """Record a finished check. Returns "recorded", "stale" or "duplicate"."""
    schedule = await db.scalar(
        select(MonitorSchedule)
        .where(
            MonitorSchedule.organization_id == job.organization_id,
            MonitorSchedule.monitor_id == job.monitor_id,
        )
        .with_for_update()
    )
    if (
        schedule is None
        or schedule.current_job_id != job.job_id
        or schedule.generation != job.generation
    ):
        await db.rollback()
        return "stale"  # superseded: edited, paused, suspended, or lease reclaimed
    monitor = await db.scalar(
        select(Monitor)
        .join(Organization, Organization.id == Monitor.organization_id)
        .where(
            Monitor.organization_id == job.organization_id,
            Monitor.id == job.monitor_id,
            Monitor.lifecycle == MonitorLifecycle.ACTIVE,
            Organization.status == OrgStatus.ACTIVE,
        )
        .with_for_update(of=Monitor)
    )
    if monitor is None:
        await db.rollback()
        return "stale"

    measurement_id = await db.scalar(
        insert(Measurement)
        .values(
            id=new_id(),
            organization_id=job.organization_id,
            monitor_id=job.monitor_id,
            job_id=job.job_id,
            trigger=job.trigger,
            source_kind="HTTP_PROBE",
            schema_version=1,
            scheduled_for=job.scheduled_for,
            observed_at=observed_at,
            ingested_at=now,
            result=outcome.result,
            failure_category=outcome.failure_category,
            http_status=outcome.http_status,
            elapsed_ms=outcome.elapsed_ms,
            attempt_count=outcome.attempt_count,
            tls_not_after=outcome.tls_not_after,
        )
        .on_conflict_do_nothing(
            index_elements=["monitor_id", "job_id"], index_where=Measurement.job_id.is_not(None)
        )
        .returning(Measurement.id)
    )
    if measurement_id is None:
        await db.rollback()
        return "duplicate"

    if job.trigger == SCHEDULED:  # check-now never affects health (FR-MON-008)
        health = await db.get(MonitorHealth, job.monitor_id, with_for_update=True)
        if health is not None:
            if outcome.result in Result.CONCLUSIVE:
                await evaluate(
                    db,
                    monitor,
                    health,
                    Observation(
                        measurement_id=measurement_id,
                        result=outcome.result,
                        failure_category=outcome.failure_category,
                        http_status=outcome.http_status,
                        elapsed_ms=outcome.elapsed_ms,
                        attempt_count=outcome.attempt_count,
                        tls_not_after=outcome.tls_not_after,
                        observed_at=observed_at,
                    ),
                )
            elif outcome.result == Result.BLOCKED:
                health.consecutive_blocked += 1
                health.version += 1
                if health.consecutive_blocked >= AUTO_PAUSE_AFTER_BLOCKED:
                    monitor.lifecycle = MonitorLifecycle.PAUSED
                    monitor.paused_reason = POLICY_BLOCKED
                    monitor.attention_reason = POLICY_BLOCKED
                    monitor.version += 1
                    schedule.generation += 1
                    await enqueue_auto_paused(
                        db, job.organization_id, job.monitor_id, schedule.generation
                    )
                    record(
                        db,
                        AuditAction.MONITOR_AUTO_PAUSED,
                        scope="ORGANIZATION",
                        organization_id=job.organization_id,
                        actor_kind="SYSTEM",
                        entity_kind="monitor",
                        entity_id=job.monitor_id,
                        details={
                            "reason": POLICY_BLOCKED,
                            "consecutive_blocked": health.consecutive_blocked,
                        },
                    )
            # INCONCLUSIVE: probe-side fault, counters untouched (FR-MON-012).
        following, missed = next_slot(schedule.next_due_at, monitor.interval_seconds, now)
        schedule.planned_due_at = schedule.next_due_at
        schedule.next_due_at = following
        schedule.missed_slots += missed
    schedule.manual_check_requested_at = None
    schedule.lease_owner = None
    schedule.lease_until = None
    schedule.current_job_id = None
    schedule.current_trigger = None
    await publish(
        db,
        job.organization_id,
        "check.recorded",
        monitor_id=job.monitor_id,
        result=outcome.result,
        trigger=job.trigger,
    )
    if monitor.lifecycle == MonitorLifecycle.PAUSED:
        await publish(
            db,
            job.organization_id,
            "monitor.lifecycle",
            monitor_id=job.monitor_id,
            lifecycle=monitor.lifecycle,
            reason=monitor.paused_reason,
        )
    await db.commit()
    return "recorded"


async def earliest_due(db: AsyncSession) -> datetime | None:
    """Next time any eligible schedule becomes due (used to sleep instead of polling)."""
    return await db.scalar(
        select(func.min(MonitorSchedule.next_due_at))
        .join(
            Monitor,
            (Monitor.organization_id == MonitorSchedule.organization_id)
            & (Monitor.id == MonitorSchedule.monitor_id),
        )
        .join(Organization, Organization.id == MonitorSchedule.organization_id)
        .where(
            Organization.status == OrgStatus.ACTIVE, Monitor.lifecycle == MonitorLifecycle.ACTIVE
        )
    )


async def release_lease(db: AsyncSession, job: ClaimedJob) -> None:
    """Give a job back (e.g. worker shutting down before it started)."""
    await db.execute(
        update(MonitorSchedule)
        .where(
            MonitorSchedule.monitor_id == job.monitor_id,
            MonitorSchedule.current_job_id == job.job_id,
        )
        .values(lease_owner=None, lease_until=None, current_job_id=None, current_trigger=None)
    )
    await db.commit()
