"""Organization overview (FR-UI-001): real counts from monitors, health, incidents and
measurements of one organization. Only display names, hosts, states, times and result codes."""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.catalog.models import Monitor, MonitorLifecycle
from sentinelops.incidents.models import Incident, IncidentStatus
from sentinelops.measurements.models import Measurement
from sentinelops.measurements.reports import Report, build_report, resolve_window, select_monitors
from sentinelops.scheduler.models import MonitorHealth

TLS_HORIZON_DAYS = 30
RECENT_ROWS = 10


@dataclass(frozen=True)
class TlsSoon:
    monitor_id: uuid.UUID
    monitor_name: str
    hostname: str
    expires_at: datetime
    days_remaining: int
    warn_days: int


@dataclass(frozen=True)
class RecentCheck:
    monitor_id: uuid.UUID
    monitor_name: str
    result: str
    failure_category: str | None
    http_status: int | None
    elapsed_ms: int | None
    trigger: str
    observed_at: datetime


@dataclass(frozen=True)
class RecentIncident:
    incident: Incident
    monitor_name: str


@dataclass(frozen=True)
class Dashboard:
    generated_at: datetime
    lifecycle_counts: dict[str, int]
    health_counts: dict[str, int]
    active_incidents_by_severity: dict[str, int]
    recent_incidents: list[RecentIncident]
    report_24h: Report
    results_24h: dict[str, int]
    tls_expiring: list[TlsSoon]
    recent_checks: list[RecentCheck]


async def build_dashboard(
    db: AsyncSession, organization_id: uuid.UUID, timezone: str, now: datetime
) -> Dashboard:
    lifecycle = {key: 0 for key in ("ACTIVE", "PAUSED", "DRAFT", "ARCHIVED")}
    for state, count in await db.execute(
        select(Monitor.lifecycle, func.count())
        .where(Monitor.organization_id == organization_id)
        .group_by(Monitor.lifecycle)
    ):
        lifecycle[state] = count
    health = {key: 0 for key in ("UP", "DEGRADED", "DOWN", "UNKNOWN")}
    for state, count in await db.execute(
        select(MonitorHealth.state, func.count())
        .join(
            Monitor,
            (Monitor.organization_id == MonitorHealth.organization_id)
            & (Monitor.id == MonitorHealth.monitor_id),
        )
        .where(
            MonitorHealth.organization_id == organization_id,
            Monitor.lifecycle == MonitorLifecycle.ACTIVE,
        )
        .group_by(MonitorHealth.state)
    ):
        health[state] = count
    severity = {"CRITICAL": 0, "WARNING": 0}
    for level, count in await db.execute(
        select(Incident.severity, func.count())
        .where(
            Incident.organization_id == organization_id,
            Incident.status != IncidentStatus.RESOLVED,
        )
        .group_by(Incident.severity)
    ):
        severity[level] = count
    recent = [
        RecentIncident(incident, name)
        for incident, name in await db.execute(
            select(Incident, Monitor.name)
            .join(
                Monitor,
                (Monitor.organization_id == Incident.organization_id)
                & (Monitor.id == Incident.monitor_id),
            )
            .where(Incident.organization_id == organization_id)
            .order_by(Incident.last_event_at.desc(), Incident.id.desc())
            .limit(RECENT_ROWS)
        )
    ]
    since = now - timedelta(hours=24)
    results = {key: 0 for key in ("PASS", "SLOW", "FAIL", "BLOCKED", "INCONCLUSIVE")}
    for result, count in await db.execute(
        select(Measurement.result, func.count())
        .where(
            Measurement.organization_id == organization_id,
            Measurement.trigger == "SCHEDULED",
            Measurement.observed_at >= since,
        )
        .group_by(Measurement.result)
    ):
        results[result] = count
    latest_tls = (
        select(
            Measurement.monitor_id,
            Measurement.tls_not_after,
        )
        .where(
            Measurement.organization_id == organization_id,
            Measurement.tls_not_after.is_not(None),
            Measurement.observed_at >= now - timedelta(days=2),
        )
        .ext(distinct_on(Measurement.monitor_id))
        .order_by(Measurement.monitor_id, Measurement.observed_at.desc())
        .subquery()
    )
    tls = [
        TlsSoon(
            monitor_id,
            name,
            hostname,
            expires,
            (expires - now).days,
            warn,
        )
        for monitor_id, name, hostname, warn, expires in await db.execute(
            select(
                Monitor.id,
                Monitor.name,
                Monitor.hostname,
                Monitor.tls_warn_days,
                latest_tls.c.tls_not_after,
            )
            .join(latest_tls, latest_tls.c.monitor_id == Monitor.id)
            .where(
                Monitor.organization_id == organization_id,
                Monitor.lifecycle == MonitorLifecycle.ACTIVE,
                latest_tls.c.tls_not_after < now + timedelta(days=TLS_HORIZON_DAYS),
            )
            .order_by(latest_tls.c.tls_not_after)
        )
    ]
    checks = [
        RecentCheck(*row)
        for row in await db.execute(
            select(
                Measurement.monitor_id,
                Monitor.name,
                Measurement.result,
                Measurement.failure_category,
                Measurement.http_status,
                Measurement.elapsed_ms,
                Measurement.trigger,
                Measurement.observed_at,
            )
            .join(
                Monitor,
                (Monitor.organization_id == Measurement.organization_id)
                & (Monitor.id == Measurement.monitor_id),
            )
            .where(Measurement.organization_id == organization_id, Measurement.observed_at >= since)
            .order_by(Measurement.observed_at.desc(), Measurement.id.desc())
            .limit(RECENT_ROWS)
        )
    ]
    monitors = await select_monitors(db, organization_id)
    window = resolve_window("24h", None, None, timezone, now)
    report = await build_report(db, organization_id, monitors, window, limit=0)
    return Dashboard(now, lifecycle, health, severity, recent, report, results, tls, checks)
