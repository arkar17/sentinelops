"""Platform dashboard aggregates (FR-PLT-002, FR-PLT-006, 03_DATABASE_DESIGN.md §5).

Reads only the aggregate views ``v_platform_org_summary``, ``v_platform_usage_daily`` and
``v_platform_queue_health``, plus ``organization`` and ``worker_heartbeat``. These carry counts
and organization metadata, never monitor names, hosts, URLs, credentials or incident content.
"""

import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

HEARTBEAT_STALE = timedelta(seconds=90)
USAGE_DAYS = 30


@dataclass(frozen=True)
class OrgUsage:
    organization_id: uuid.UUID
    slug: str
    name: str
    status: str
    created_at: datetime
    active_members: int
    monitors_active: int
    monitors_paused: int
    monitors_draft: int
    monitors_archived: int
    status_pages: int
    channels: int
    open_incidents_critical: int
    open_incidents_warning: int
    max_monitors: int
    max_status_pages: int
    max_channels: int

    @property
    def monitors_live(self) -> int:
        return self.monitors_active + self.monitors_paused + self.monitors_draft


@dataclass(frozen=True)
class DailyUsage:
    day: date
    checks: int
    fail: int
    blocked: int
    inconclusive: int
    incidents_opened: int
    notifications_sent: int
    notification_failures: int


@dataclass(frozen=True)
class QueueHealth:
    due_backlog: int
    oldest_due_seconds: float | None
    checks_in_flight: int
    checks_last_15m: int
    checks_last_24h: int
    outbox_pending: int
    outbox_leased: int
    outbox_oldest_due_seconds: float | None
    outbox_failed_24h: int

    @property
    def checks_per_minute(self) -> float:
        return round(self.checks_last_15m / 15, 2)


@dataclass(frozen=True)
class WorkerStatus:
    worker_id: str
    kind: str
    last_seen_at: datetime
    in_flight: int
    alive: bool


@dataclass(frozen=True)
class PlatformUsage:
    organizations: list[OrgUsage]
    daily: list[DailyUsage]
    queue: QueueHealth
    workers: list[WorkerStatus]
    organizations_created_30d: int


async def platform_usage(db: AsyncSession, now: datetime) -> PlatformUsage:
    orgs = [
        OrgUsage(*row)
        for row in await db.execute(
            text(
                "SELECT organization_id, slug, name, status, created_at, active_members, "
                "monitors_active, monitors_paused, monitors_draft, monitors_archived, "
                "status_pages, channels, open_incidents_critical, open_incidents_warning, "
                "max_monitors, max_status_pages, max_channels "
                "FROM v_platform_org_summary ORDER BY lower(name)"
            )
        )
    ]
    daily = [
        DailyUsage(*row)
        for row in await db.execute(
            text(
                "SELECT day, sum(checks)::int, sum(fail)::int, sum(blocked)::int, "
                "sum(inconclusive)::int, sum(incidents_opened)::int, "
                "sum(notifications_sent)::int, sum(notification_failures)::int "
                "FROM v_platform_usage_daily WHERE day >= :since GROUP BY day ORDER BY day"
            ),
            {"since": (now - timedelta(days=USAGE_DAYS)).date()},
        )
    ]
    queue_row = (await db.execute(text("SELECT * FROM v_platform_queue_health"))).one()
    queue = QueueHealth(
        int(queue_row.due_backlog),
        float(queue_row.oldest_due_seconds) if queue_row.oldest_due_seconds is not None else None,
        int(queue_row.checks_in_flight),
        int(queue_row.checks_last_15m),
        int(queue_row.checks_last_24h),
        int(queue_row.outbox_pending),
        int(queue_row.outbox_leased),
        float(queue_row.outbox_oldest_due_seconds)
        if queue_row.outbox_oldest_due_seconds is not None
        else None,
        int(queue_row.outbox_failed_24h),
    )
    workers = [
        WorkerStatus(worker_id, kind, seen, in_flight, now - seen <= HEARTBEAT_STALE)
        for worker_id, kind, seen, in_flight in await db.execute(
            text(
                "SELECT worker_id, kind, last_seen_at, in_flight FROM worker_heartbeat "
                "WHERE last_seen_at > :since ORDER BY kind, worker_id"
            ),
            {"since": now - timedelta(days=1)},
        )
    ]
    created = await db.scalar(
        text("SELECT count(*) FROM organization WHERE created_at >= :since"),
        {"since": now - timedelta(days=30)},
    )
    return PlatformUsage(orgs, daily, queue, workers, int(created or 0))
