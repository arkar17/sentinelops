"""Automatic incident transitions, run inside the worker's completion transaction (FR-INC-006).

The caller (``scheduler.service.complete_job``) has already verified the job and generation,
inserted the measurement idempotently and locked the schedule, monitor and health rows, so
duplicate or late completions never reach this code and evaluations of one monitor are
serialized. Health, incidents, events and audit commit together with the measurement.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.audit.service import AuditAction, record
from sentinelops.catalog.models import Monitor, MonitorLifecycle
from sentinelops.db.base import new_id
from sentinelops.incidents import health as hsm
from sentinelops.incidents.events import emit
from sentinelops.incidents.models import (
    EventType,
    Incident,
    IncidentStatus,
    IncidentType,
    Resolution,
    Severity,
)
from sentinelops.realtime.publish import publish
from sentinelops.scheduler.models import MonitorHealth
from sentinelops.tenancy.models import Organization, OrgStatus

TITLES = {
    IncidentType.OUTAGE: "Outage detected",
    IncidentType.TLS_EXPIRY: "TLS certificate expiring",
}
STALE_AFTER_INTERVALS = 3  # FR-MON-012
SEVERITIES = {IncidentType.OUTAGE: Severity.CRITICAL, IncidentType.TLS_EXPIRY: Severity.WARNING}


@dataclass(frozen=True)
class Observation:
    """A scheduled conclusive measurement, already stored (normalized; no URL/host/body)."""

    measurement_id: uuid.UUID
    result: str
    failure_category: str | None
    http_status: int | None
    elapsed_ms: int | None
    attempt_count: int
    tls_not_after: datetime | None
    observed_at: datetime

    def evidence(self) -> dict[str, Any]:
        return {
            "measurement_id": str(self.measurement_id),
            "result": self.result,
            "failure_category": self.failure_category,
            "http_status": self.http_status,
            "elapsed_ms": self.elapsed_ms,
            "attempt_count": self.attempt_count,
            "observed_at": self.observed_at.isoformat(),
        }


async def active_incidents(
    db: AsyncSession, organization_id: uuid.UUID, monitor_id: uuid.UUID
) -> dict[str, Incident]:
    rows = await db.scalars(
        select(Incident)
        .where(
            Incident.organization_id == organization_id,
            Incident.monitor_id == monitor_id,
            Incident.status != IncidentStatus.RESOLVED,
        )
        .with_for_update()
    )
    return {incident.type: incident for incident in rows}


def _audit_system(db: AsyncSession, action: str, incident: Incident, **details: Any) -> None:
    record(
        db,
        action,
        scope="ORGANIZATION",
        organization_id=incident.organization_id,
        actor_kind="SYSTEM",
        entity_kind="incident",
        entity_id=incident.id,
        details={"type": incident.type, "monitor_id": str(incident.monitor_id), **details},
    )


async def _open(
    db: AsyncSession, monitor: Monitor, kind: str, obs: Observation, details: dict[str, Any]
) -> Incident:
    incident = Incident(
        id=new_id(),
        organization_id=monitor.organization_id,
        monitor_id=monitor.id,
        type=kind,
        source_kind="HTTP_PROBE",
        severity=SEVERITIES[kind],
        status=IncidentStatus.OPEN,
        title_sanitized=TITLES[kind],
        opened_measurement_id=obs.measurement_id,
        opened_at=obs.observed_at,
        last_event_at=obs.observed_at,
        version=1,
    )
    db.add(incident)
    await emit(db, incident, EventType.OPENED, at=obs.observed_at, details=details)
    _audit_system(db, AuditAction.INCIDENT_OPENED, incident, severity=incident.severity)
    return incident


async def _auto_resolve(
    db: AsyncSession, incident: Incident, obs: Observation, details: dict[str, Any]
) -> None:
    incident.status = IncidentStatus.RESOLVED
    incident.resolved_at = obs.observed_at
    incident.resolution = Resolution.AUTO
    incident.version += 1
    duration = int((obs.observed_at - incident.opened_at).total_seconds())
    await emit(
        db,
        incident,
        EventType.RESOLVED,
        at=obs.observed_at,
        details={"resolution": Resolution.AUTO, "duration_seconds_estimate": duration, **details},
    )
    _audit_system(db, AuditAction.INCIDENT_AUTO_RESOLVED, incident, resolution=Resolution.AUTO)


def _tls_details(obs: Observation, not_after: datetime, warn_days: int) -> dict[str, Any]:
    remaining = hsm.tls_remaining(not_after, obs.observed_at)
    return {
        "tls_not_after": not_after.isoformat(),
        "days_remaining": remaining.days,
        "threshold_days": warn_days,
        "evidence": obs.evidence(),
    }


async def evaluate(
    db: AsyncSession, monitor: Monitor, health: MonitorHealth, obs: Observation
) -> hsm.Step | None:
    """Apply one scheduled conclusive result. Returns None if it was older than the newest
    applied result (out of order), in which case nothing changes."""
    if health.last_conclusive_at is not None and obs.observed_at <= health.last_conclusive_at:
        return None
    active = await active_incidents(db, monitor.organization_id, monitor.id)
    outage = active.get(IncidentType.OUTAGE)
    result = hsm.step(
        hsm.Health(health.state),
        hsm.Counters(
            failures=health.consecutive_failures,
            successes=health.consecutive_successes,
            passes=health.consecutive_passes,
            slow=health.consecutive_slow,
        ),
        obs.result,
        failure_threshold=monitor.failure_threshold,
        recovery_threshold=monitor.recovery_threshold,
        outage_active=outage is not None,
    )
    health.consecutive_failures = result.counters.failures
    health.consecutive_successes = result.counters.successes
    health.consecutive_passes = result.counters.passes
    health.consecutive_slow = result.counters.slow
    health.consecutive_blocked = 0
    health.last_measurement_id = obs.measurement_id
    health.last_conclusive_at = obs.observed_at
    if result.changed:
        health.state = result.state
        health.last_change_at = obs.observed_at
        await publish(
            db,
            monitor.organization_id,
            "monitor.health",
            monitor_id=monitor.id,
            state=result.state.value,
            previous=result.previous.value,
        )
    health.version += 1

    transition = {"health_from": result.previous.value, "health_to": result.state.value}
    action = hsm.outage_action(result, outage_active=outage is not None)
    if action == "open":
        await _open(
            db,
            monitor,
            IncidentType.OUTAGE,
            obs,
            {
                **transition,
                "consecutive_failures": result.counters.failures,
                "failure_threshold": monitor.failure_threshold,
                "evidence": obs.evidence(),
            },
        )
    elif action == "resolve" and outage is not None:
        await _auto_resolve(
            db,
            outage,
            obs,
            {
                **transition,
                "consecutive_successes": result.counters.successes,
                "recovery_threshold": monitor.recovery_threshold,
                "evidence": obs.evidence(),
            },
        )

    tls = active.get(IncidentType.TLS_EXPIRY)
    not_after = obs.tls_not_after
    if not_after is not None:
        warn_days = monitor.tls_warn_days
        action = hsm.tls_action(
            not_after, obs.observed_at, warn_days=warn_days, tls_active=tls is not None
        )
        if action == "open":
            await _open(
                db, monitor, IncidentType.TLS_EXPIRY, obs, _tls_details(obs, not_after, warn_days)
            )
        elif action == "resolve" and tls is not None:
            await _auto_resolve(db, tls, obs, _tls_details(obs, not_after, warn_days))
    return result


async def mark_stale(db: AsyncSession, now: datetime) -> int:
    """Health becomes UNKNOWN when no conclusive scheduled result arrived for 3 intervals
    (FR-MON-012). Counters restart so fresh evidence is required; incidents are not resolved
    (02_TECHNICAL_ARCHITECTURE.md §5). No commit."""
    window = func.make_interval(0, 0, 0, 0, 0, 0, Monitor.interval_seconds * STALE_AFTER_INTERVALS)
    result = await db.execute(
        update(MonitorHealth)
        .where(
            MonitorHealth.organization_id == Monitor.organization_id,
            MonitorHealth.monitor_id == Monitor.id,
            Organization.id == Monitor.organization_id,
            Monitor.lifecycle == MonitorLifecycle.ACTIVE,
            Organization.status == OrgStatus.ACTIVE,
            MonitorHealth.state != hsm.Health.UNKNOWN,
            or_(
                MonitorHealth.last_conclusive_at.is_(None),
                MonitorHealth.last_conclusive_at + window < now,
            ),
        )
        .values(
            state=hsm.Health.UNKNOWN.value,
            consecutive_failures=0,
            consecutive_successes=0,
            consecutive_passes=0,
            consecutive_slow=0,
            last_change_at=now,
            version=MonitorHealth.version + 1,
        )
        .execution_options(synchronize_session=False)
    )
    return int(getattr(result, "rowcount", 0) or 0)
