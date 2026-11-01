"""Monitor eligibility and schedule/health maintenance shared by catalog, platform and worker.

No secrets are touched here, so the platform plane may use it (ADR-005, import-linter).
"""

import random
import uuid
from datetime import datetime, timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.catalog.models import (
    DomainStatus,
    Monitor,
    MonitorLifecycle,
    VerifiedDomain,
)
from sentinelops.scheduler.models import MonitorHealth, MonitorSchedule

DOMAIN_UNVERIFIED = "DOMAIN_UNVERIFIED"
POLICY_BLOCKED = "POLICY_BLOCKED"
MAX_INITIAL_JITTER_SECONDS = 60


def initial_due(now: datetime, interval_seconds: int) -> datetime:
    """First run after activation, jittered to spread load (FR-MON-005)."""
    jitter = random.uniform(0, min(interval_seconds, MAX_INITIAL_JITTER_SECONDS))  # noqa: S311
    return now + timedelta(seconds=jitter)


async def covering_domain(
    db: AsyncSession, organization_id: uuid.UUID, hostname: str, now: datetime
) -> VerifiedDomain | None:
    """A VERIFIED, unexpired domain of this organization equal to or a parent of ``hostname``."""
    labels = hostname.split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    return await db.scalar(
        select(VerifiedDomain)
        .where(
            VerifiedDomain.organization_id == organization_id,
            VerifiedDomain.fqdn.in_(candidates),
            VerifiedDomain.status == DomainStatus.VERIFIED,
            VerifiedDomain.expires_at > now,
        )
        .limit(1)
    )


async def reset_health(db: AsyncSession, organization_id: uuid.UUID, monitor_id: uuid.UUID) -> None:
    await db.execute(
        update(MonitorHealth)
        .where(
            MonitorHealth.organization_id == organization_id, MonitorHealth.monitor_id == monitor_id
        )
        .values(
            state="UNKNOWN",
            consecutive_failures=0,
            consecutive_successes=0,
            consecutive_slow=0,
            consecutive_passes=0,
            consecutive_blocked=0,
            last_change_at=clock.now(),
            version=MonitorHealth.version + 1,
        )
    )


async def reschedule(db: AsyncSession, monitor: Monitor, *, now: datetime, run_soon: bool) -> None:
    """Invalidate in-flight jobs (generation) and set the next due time."""
    values: dict[str, object] = {
        "generation": MonitorSchedule.generation + 1,
        "lease_owner": None,
        "lease_until": None,
        "current_job_id": None,
        "current_trigger": None,
    }
    if run_soon:
        values["next_due_at"] = initial_due(now, monitor.interval_seconds)
        values["planned_due_at"] = None
    await db.execute(
        update(MonitorSchedule)
        .where(
            MonitorSchedule.organization_id == monitor.organization_id,
            MonitorSchedule.monitor_id == monitor.id,
        )
        .values(**values)
    )


async def activate_covered_monitors(db: AsyncSession, organization_id: uuid.UUID) -> int:
    """DRAFT monitors waiting for domain verification become ACTIVE once covered. No commit."""
    now = clock.now()
    drafts = list(
        await db.scalars(
            select(Monitor)
            .where(
                Monitor.organization_id == organization_id,
                Monitor.lifecycle == MonitorLifecycle.DRAFT,
                or_(
                    Monitor.attention_reason == DOMAIN_UNVERIFIED,
                    Monitor.attention_reason.is_(None),
                ),
            )
            .with_for_update()
        )
    )
    activated = 0
    for monitor in drafts:
        if await covering_domain(db, organization_id, monitor.hostname, now) is None:
            continue
        monitor.lifecycle = MonitorLifecycle.ACTIVE
        monitor.attention_reason = None
        monitor.version += 1
        await reset_health(db, organization_id, monitor.id)
        await reschedule(db, monitor, now=now, run_soon=True)
        activated += 1
    return activated


async def bump_organization_generations(db: AsyncSession, organization_id: uuid.UUID) -> None:
    """Organization suspension/activation: stale jobs from before the change are discarded."""
    await db.execute(
        update(MonitorSchedule)
        .where(MonitorSchedule.organization_id == organization_id)
        .values(
            generation=MonitorSchedule.generation + 1,
            lease_owner=None,
            lease_until=None,
            current_job_id=None,
            current_trigger=None,
            manual_check_requested_at=None,
        )
    )


async def reset_organization_health(db: AsyncSession, organization_id: uuid.UUID) -> None:
    """Organization activation: monitors resume with health UNKNOWN (FR-PLT-004)."""
    now = clock.now()
    await db.execute(
        update(MonitorHealth)
        .where(MonitorHealth.organization_id == organization_id)
        .values(
            state="UNKNOWN",
            consecutive_failures=0,
            consecutive_successes=0,
            consecutive_slow=0,
            consecutive_passes=0,
            consecutive_blocked=0,
            last_change_at=now,
            version=MonitorHealth.version + 1,
        )
    )
    await db.execute(
        update(MonitorSchedule)
        .where(MonitorSchedule.organization_id == organization_id)
        .values(next_due_at=now)
    )
