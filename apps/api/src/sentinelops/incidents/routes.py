"""Incident routes under /api/orgs/{org_id}/incidents. Each route declares one permission action.

Responses carry sanitized fields only: monitor display name and host, generic titles, result
evidence (category, status code, timing) and member comments. Never URLs, query strings,
headers, bodies or resolved IPs.
"""

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field

from sentinelops.db.session import DbSession
from sentinelops.incidents import service
from sentinelops.incidents.models import IncidentStatus, IncidentType
from sentinelops.tenancy.context import OrgContext, OrgPermission

router = APIRouter(prefix="/api/orgs/{org_id}/incidents", tags=["incidents"])

StatusName = Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]


def Ctx(action: str) -> Any:  # noqa: N802  # reads like a type in signatures
    return Depends(OrgPermission(action))


class MonitorRef(BaseModel):
    id: uuid.UUID
    name: str
    hostname: str


class IncidentOut(BaseModel):
    id: uuid.UUID
    type: str
    severity: str
    status: str
    source_kind: str
    title: str
    monitor: MonitorRef
    opened_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    resolution: str | None
    assigned_user_id: uuid.UUID | None
    assignee_email: str | None
    last_event_at: datetime
    duration_seconds: int | None
    # Outage duration is derived from detection and recovery checks, not exact downtime.
    duration_is_estimate: bool
    version: int


class IncidentPage(BaseModel):
    items: list[IncidentOut]
    total: int


class EventOut(BaseModel):
    id: uuid.UUID
    event_type: str
    actor_kind: str
    actor_user_id: uuid.UUID | None
    actor_email: str | None
    created_at: datetime
    details: dict[str, Any]


class IncidentDetailOut(IncidentOut):
    monitor_health: str
    monitor_lifecycle: str
    events: list[EventOut]


class VersionIn(BaseModel):
    version: int | None = None


class AssignIn(VersionIn):
    user_id: uuid.UUID | None


class CommentIn(BaseModel):
    text: str = Field(min_length=1, max_length=service.MAX_COMMENT)


class ResolveIn(VersionIn):
    note: str | None = Field(default=None, max_length=service.MAX_COMMENT)


def _out(row: service.IncidentRow) -> dict[str, Any]:
    i = row.incident
    duration = None
    if i.resolved_at is not None:
        duration = int((i.resolved_at - i.opened_at).total_seconds())
    return {
        "id": i.id,
        "type": i.type,
        "severity": i.severity,
        "status": i.status,
        "source_kind": i.source_kind,
        "title": i.title_sanitized,
        "monitor": MonitorRef(
            id=i.monitor_id, name=row.monitor_name, hostname=row.monitor_hostname
        ),
        "opened_at": i.opened_at,
        "acknowledged_at": i.acknowledged_at,
        "resolved_at": i.resolved_at,
        "resolution": i.resolution,
        "assigned_user_id": i.assigned_user_id,
        "assignee_email": row.assignee_email,
        "last_event_at": i.last_event_at,
        "duration_seconds": duration,
        "duration_is_estimate": i.type == IncidentType.OUTAGE,
        "version": i.version,
    }


async def _detail(db: DbSession, ctx: OrgContext, incident_id: uuid.UUID) -> IncidentDetailOut:
    detail = await service.get_incident(db, ctx, incident_id)
    return IncidentDetailOut(
        **_out(detail.row),
        monitor_health=detail.health_state,
        monitor_lifecycle=detail.monitor_lifecycle,
        events=[
            EventOut(
                id=e.event.id,
                event_type=e.event.event_type,
                actor_kind=e.event.actor_kind,
                actor_user_id=e.event.actor_user_id,
                actor_email=e.actor_email,
                created_at=e.event.created_at,
                details=e.event.details_sanitized_json,
            )
            for e in detail.events
        ],
    )


@router.get("", response_model=IncidentPage)
async def list_incidents(
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("INC.view")],
    status_: Annotated[list[StatusName] | None, Query(alias="status")] = None,
    active: bool | None = None,
    type: Literal["OUTAGE", "TLS_EXPIRY"] | None = None,  # API field name
    severity: Literal["CRITICAL", "WARNING"] | None = None,
    monitor_id: uuid.UUID | None = None,
    assigned_user_id: uuid.UUID | None = None,
    unassigned: bool = False,
    opened_after: datetime | None = None,
    opened_before: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=10000)] = 0,
) -> IncidentPage:
    statuses: list[str] | None = list(status_) if status_ else None
    if active is True:
        statuses = [IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED]
    elif active is False:
        statuses = [IncidentStatus.RESOLVED]
    rows, total = await service.list_incidents(
        db,
        ctx,
        service.IncidentFilters(
            statuses=statuses,
            type=type,
            severity=severity,
            monitor_id=monitor_id,
            assigned_user_id=assigned_user_id,
            unassigned=unassigned,
            opened_after=opened_after,
            opened_before=opened_before,
            limit=limit,
            offset=offset,
        ),
    )
    return IncidentPage(items=[IncidentOut(**_out(r)) for r in rows], total=total)


@router.get("/{incident_id}", response_model=IncidentDetailOut)
async def get_incident(
    incident_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("INC.view")]
) -> IncidentDetailOut:
    return await _detail(db, ctx, incident_id)


@router.post("/{incident_id}/acknowledge", response_model=IncidentDetailOut)
async def acknowledge(
    incident_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("INC.acknowledge")],
    body: VersionIn | None = None,
) -> IncidentDetailOut:
    await service.acknowledge(db, ctx, incident_id, body.version if body else None)
    return await _detail(db, ctx, incident_id)


@router.post("/{incident_id}/assign", response_model=IncidentDetailOut)
async def assign(
    incident_id: uuid.UUID,
    body: AssignIn,
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("INC.assign")],
) -> IncidentDetailOut:
    await service.assign(db, ctx, incident_id, body.user_id, body.version)
    return await _detail(db, ctx, incident_id)


@router.post(
    "/{incident_id}/comments",
    response_model=IncidentDetailOut,
    status_code=status.HTTP_201_CREATED,
)
async def add_comment(
    incident_id: uuid.UUID,
    body: CommentIn,
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("INC.comment")],
) -> IncidentDetailOut:
    await service.comment(db, ctx, incident_id, body.text)
    return await _detail(db, ctx, incident_id)


@router.post("/{incident_id}/resolve", response_model=IncidentDetailOut)
async def resolve(
    incident_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("INC.resolve")],
    body: ResolveIn | None = None,
) -> IncidentDetailOut:
    await service.resolve(
        db, ctx, incident_id, body.note if body else None, body.version if body else None
    )
    return await _detail(db, ctx, incident_id)
