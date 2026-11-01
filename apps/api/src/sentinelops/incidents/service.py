"""Incident reads and member operations (FR-INC-004/005, FR-UI-003). All queries are
organization-scoped from the validated path context; another organization's incident is 404.

Lifecycle OPEN → ACKNOWLEDGED → RESOLVED (or OPEN → RESOLVED). Resolved incidents are never
reopened. Manual resolution of an OUTAGE is refused while its monitor is ACTIVE and DOWN.
Each change appends one timeline event and one audit event in the same transaction. Comments are
member-visible text; audit records only their length.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.catalog.models import Monitor, MonitorLifecycle
from sentinelops.errors import AppError
from sentinelops.identity.models import AppUser
from sentinelops.incidents.events import emit
from sentinelops.incidents.health import Health
from sentinelops.incidents.models import (
    EventType,
    Incident,
    IncidentEvent,
    IncidentStatus,
    IncidentType,
    Resolution,
)
from sentinelops.scheduler.models import MonitorHealth
from sentinelops.tenancy.context import OrgContext
from sentinelops.tenancy.models import MemberStatus, OrganizationMember

MAX_COMMENT = 2000


def _not_found() -> AppError:
    return AppError(404, "NOT_FOUND", "Incident not found")


def clean_text(value: str, field: str) -> str:
    """Plain text, 1-2000 characters, no control characters except newline and tab."""
    text = value.strip()
    if not 1 <= len(text) <= MAX_COMMENT:
        raise AppError(422, "INVALID_TEXT", f"The {field} must be 1-{MAX_COMMENT} characters")
    if any(ord(ch) < 32 and ch not in "\n\t" for ch in text) or "\x7f" in text:
        raise AppError(422, "INVALID_TEXT", f"The {field} contains unsupported characters")
    return text


# --- reads ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class IncidentFilters:
    statuses: list[str] | None = None
    type: str | None = None
    severity: str | None = None
    monitor_id: uuid.UUID | None = None
    assigned_user_id: uuid.UUID | None = None
    unassigned: bool = False
    opened_after: datetime | None = None
    opened_before: datetime | None = None
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True)
class IncidentRow:
    incident: Incident
    monitor_name: str
    monitor_hostname: str
    assignee_email: str | None


@dataclass(frozen=True)
class EventRow:
    event: IncidentEvent
    actor_email: str | None


@dataclass(frozen=True)
class IncidentDetail:
    row: IncidentRow
    health_state: str
    monitor_lifecycle: str
    events: list[EventRow]


_Assignee = aliased(AppUser)


def _base(ctx: OrgContext) -> Select[Incident, str, str, str]:
    return (
        select(Incident, Monitor.name, Monitor.hostname, _Assignee.email)
        .join(
            Monitor,
            (Monitor.organization_id == Incident.organization_id)
            & (Monitor.id == Incident.monitor_id),
        )
        .outerjoin(_Assignee, _Assignee.id == Incident.assigned_user_id)
        .where(Incident.organization_id == ctx.organization_id)
    )


async def list_incidents(
    db: AsyncSession, ctx: OrgContext, filters: IncidentFilters
) -> tuple[list[IncidentRow], int]:
    stmt = _base(ctx)
    if filters.statuses:
        stmt = stmt.where(Incident.status.in_(filters.statuses))
    if filters.type:
        stmt = stmt.where(Incident.type == filters.type)
    if filters.severity:
        stmt = stmt.where(Incident.severity == filters.severity)
    if filters.monitor_id:
        stmt = stmt.where(Incident.monitor_id == filters.monitor_id)
    if filters.assigned_user_id:
        stmt = stmt.where(Incident.assigned_user_id == filters.assigned_user_id)
    if filters.unassigned:
        stmt = stmt.where(Incident.assigned_user_id.is_(None))
    if filters.opened_after:
        stmt = stmt.where(Incident.opened_at >= filters.opened_after)
    if filters.opened_before:
        stmt = stmt.where(Incident.opened_at < filters.opened_before)
    total = int(await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    rows = await db.execute(
        stmt.order_by(Incident.opened_at.desc(), Incident.id.desc())
        .limit(filters.limit)
        .offset(filters.offset)
    )
    return [IncidentRow(i, name, host, email) for i, name, host, email in rows], total


async def get_incident(db: AsyncSession, ctx: OrgContext, incident_id: uuid.UUID) -> IncidentDetail:
    found = (await db.execute(_base(ctx).where(Incident.id == incident_id))).one_or_none()
    if found is None:
        raise _not_found()
    incident, name, host, email = found
    state = await db.execute(
        select(MonitorHealth.state, Monitor.lifecycle)
        .join(
            Monitor,
            (Monitor.organization_id == MonitorHealth.organization_id)
            & (Monitor.id == MonitorHealth.monitor_id),
        )
        .where(
            MonitorHealth.organization_id == ctx.organization_id,
            MonitorHealth.monitor_id == incident.monitor_id,
        )
    )
    health_state, lifecycle = state.one()
    events = await db.execute(
        select(IncidentEvent, AppUser.email)
        .outerjoin(AppUser, AppUser.id == IncidentEvent.actor_user_id)
        .where(
            IncidentEvent.organization_id == ctx.organization_id,
            IncidentEvent.incident_id == incident.id,
        )
        .order_by(IncidentEvent.created_at, IncidentEvent.id)
    )
    return IncidentDetail(
        IncidentRow(incident, name, host, email),
        health_state,
        lifecycle,
        [EventRow(e, actor) for e, actor in events],
    )


# --- operations -------------------------------------------------------------------------------


async def _lock(db: AsyncSession, ctx: OrgContext, incident_id: uuid.UUID) -> Incident:
    incident = await db.scalar(
        select(Incident)
        .where(Incident.organization_id == ctx.organization_id, Incident.id == incident_id)
        .with_for_update()
    )
    if incident is None:
        raise _not_found()
    return incident


def _check_open(incident: Incident, version: int | None) -> None:
    if incident.status == IncidentStatus.RESOLVED:
        raise AppError(409, "INCIDENT_RESOLVED", "This incident is resolved and cannot change")
    if version is not None and version != incident.version:
        raise AppError(409, "VERSION_CONFLICT", "The incident changed; reload and try again")


def _audit(
    db: AsyncSession, ctx: OrgContext, action: str, incident: Incident, **details: Any
) -> None:
    record(
        db,
        action,
        scope="ORGANIZATION",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        actor_plane="ORG",
        entity_kind="incident",
        entity_id=incident.id,
        details={"type": incident.type, **details},
    )


async def acknowledge(
    db: AsyncSession, ctx: OrgContext, incident_id: uuid.UUID, version: int | None
) -> None:
    """OPEN → ACKNOWLEDGED. Acknowledging an acknowledged incident is a no-op."""
    incident = await _lock(db, ctx, incident_id)
    if incident.status == IncidentStatus.ACKNOWLEDGED:
        return
    _check_open(incident, version)
    now = clock.now()
    incident.status = IncidentStatus.ACKNOWLEDGED
    incident.acknowledged_at = now
    incident.acknowledged_by = ctx.user_id
    incident.version += 1
    await emit(db, incident, EventType.ACKNOWLEDGED, at=now, actor_user_id=ctx.user_id)
    _audit(db, ctx, AuditAction.INCIDENT_ACKNOWLEDGED, incident)
    await db.commit()


async def assign(
    db: AsyncSession,
    ctx: OrgContext,
    incident_id: uuid.UUID,
    assignee_id: uuid.UUID | None,
    version: int | None,
) -> None:
    """Assign to an ACTIVE member of this organization, or unassign with None."""
    if assignee_id is not None:
        # FOR SHARE: a concurrent suspension/removal waits, then unassigns (tenancy hook).
        member = await db.scalar(
            select(OrganizationMember.user_id)
            .where(
                OrganizationMember.organization_id == ctx.organization_id,
                OrganizationMember.user_id == assignee_id,
                OrganizationMember.status == MemberStatus.ACTIVE,
            )
            .with_for_update(read=True)
        )
        if member is None:
            raise AppError(
                422, "ASSIGNEE_NOT_MEMBER", "Choose an active member of this organization"
            )
    incident = await _lock(db, ctx, incident_id)
    _check_open(incident, version)
    if incident.assigned_user_id == assignee_id:
        return
    now = clock.now()
    previous = incident.assigned_user_id
    incident.assigned_user_id = assignee_id
    incident.version += 1
    details: dict[str, Any] = {
        "assignee_user_id": str(assignee_id) if assignee_id else None,
        "previous_assignee_user_id": str(previous) if previous else None,
    }
    await emit(
        db,
        incident,
        EventType.ASSIGNED if assignee_id else EventType.UNASSIGNED,
        at=now,
        actor_user_id=ctx.user_id,
        details=details,
    )
    _audit(db, ctx, AuditAction.INCIDENT_ASSIGNED, incident, **details)
    await db.commit()


async def comment(db: AsyncSession, ctx: OrgContext, incident_id: uuid.UUID, text: str) -> None:
    """Operational note; allowed on resolved incidents too (it never changes status)."""
    body = clean_text(text, "comment")
    incident = await _lock(db, ctx, incident_id)
    now = clock.now()
    incident.version += 1
    await emit(
        db, incident, EventType.COMMENTED, at=now, actor_user_id=ctx.user_id, details={"text": body}
    )
    _audit(db, ctx, AuditAction.INCIDENT_COMMENTED, incident, length=len(body))
    await db.commit()


async def resolve(
    db: AsyncSession,
    ctx: OrgContext,
    incident_id: uuid.UUID,
    note: str | None,
    version: int | None,
) -> None:
    body = clean_text(note, "resolution note") if note is not None else None
    monitor_id = await db.scalar(
        select(Incident.monitor_id).where(
            Incident.organization_id == ctx.organization_id, Incident.id == incident_id
        )
    )
    if monitor_id is None:
        raise _not_found()
    # Lock order health → incident matches the worker's evaluation, so a concurrent transition
    # to DOWN cannot slip between the check below and this commit.
    health = await db.scalar(
        select(MonitorHealth.state)
        .where(
            MonitorHealth.organization_id == ctx.organization_id,
            MonitorHealth.monitor_id == monitor_id,
        )
        .with_for_update()
    )
    lifecycle = await db.scalar(
        select(Monitor.lifecycle).where(
            Monitor.organization_id == ctx.organization_id, Monitor.id == monitor_id
        )
    )
    incident = await _lock(db, ctx, incident_id)
    _check_open(incident, version)
    if (
        incident.type == IncidentType.OUTAGE
        and lifecycle == MonitorLifecycle.ACTIVE
        and health == Health.DOWN
    ):
        raise AppError(
            409,
            "OUTAGE_STILL_DOWN",
            "The monitor is still down. Acknowledge the incident or pause the monitor instead",
        )
    now = clock.now()
    incident.status = IncidentStatus.RESOLVED
    incident.resolved_at = now
    incident.resolved_by = ctx.user_id
    incident.resolution = Resolution.MANUAL
    incident.version += 1
    details: dict[str, Any] = {
        "resolution": Resolution.MANUAL,
        "duration_seconds_estimate": int((now - incident.opened_at).total_seconds()),
    }
    if body:
        details["note"] = body
    await emit(db, incident, EventType.RESOLVED, at=now, actor_user_id=ctx.user_id, details=details)
    _audit(db, ctx, AuditAction.INCIDENT_RESOLVED, incident, resolution=Resolution.MANUAL)
    await db.commit()
