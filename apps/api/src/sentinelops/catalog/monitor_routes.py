"""Monitor routes under /api/orgs/{org_id}/monitors. Each route declares one permission action.

Role-dependent fields: VIEWER gets name, host and status; MON.view_config holders also get the
configuration (display URL without query string, header count, never header names or values).
"""

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, Field

from sentinelops.catalog import monitors
from sentinelops.catalog.models import Monitor
from sentinelops.db.session import DbSession
from sentinelops.measurements.models import Measurement
from sentinelops.secrets.cipher import SecretBox
from sentinelops.tenancy.context import OrgContext, OrgPermission

router = APIRouter(prefix="/api/orgs/{org_id}/monitors", tags=["monitors"])


def Ctx(action: str) -> Any:  # noqa: N802  # reads like a type in signatures
    return Depends(OrgPermission(action))


def _box(request: Request) -> SecretBox:
    box: SecretBox = request.app.state.secret_box
    return box


Box = Annotated[SecretBox, Depends(_box)]


class SubstringRule(BaseModel):
    type: Literal["substring"]
    value: str = Field(min_length=1, max_length=200)


class JsonPathRule(BaseModel):
    type: Literal["json_path"]
    path: str = Field(min_length=1, max_length=200)
    equals: str | int | float | bool | None


class MonitorIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    project_id: uuid.UUID
    url: str = Field(min_length=8, max_length=2048)
    method: Literal["GET", "HEAD"] = "GET"
    interval_seconds: Literal[60, 120, 300] = 60
    timeout_ms: int = Field(default=10000, ge=3000, le=15000)
    retry_attempts: int = Field(default=1, ge=0, le=2)
    expected_status: list[str | int] = Field(default_factory=lambda: ["200-299"], max_length=20)
    validation: SubstringRule | JsonPathRule | None = None
    latency_threshold_ms: int | None = Field(default=None, ge=1, le=15000)
    failure_threshold: int = Field(default=3, ge=1, le=10)
    recovery_threshold: int = Field(default=2, ge=1, le=10)
    tls_warn_days: int = Field(default=14, ge=1, le=90)
    tags: list[Annotated[str, Field(min_length=1, max_length=32)]] = Field(
        default_factory=list[str], max_length=10
    )

    def to_input(self) -> monitors.MonitorInput:
        return monitors.MonitorInput(
            name=self.name.strip(),
            project_id=self.project_id,
            url=self.url,
            method=self.method,
            interval_seconds=self.interval_seconds,
            timeout_ms=self.timeout_ms,
            retry_attempts=self.retry_attempts,
            expected_status=self.expected_status,
            validation=self.validation.model_dump() if self.validation else None,
            latency_threshold_ms=self.latency_threshold_ms,
            failure_threshold=self.failure_threshold,
            recovery_threshold=self.recovery_threshold,
            tls_warn_days=self.tls_warn_days,
            tags=self.tags,
        )


class MonitorUpdate(MonitorIn):
    version: int


class HeaderIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    value: str = Field(max_length=2048)


class HeadersIn(BaseModel):
    headers: list[HeaderIn] = Field(max_length=5)


class LatestOut(BaseModel):
    result: str
    failure_category: str | None
    http_status: int | None
    elapsed_ms: int | None
    observed_at: datetime


class MonitorConfigOut(BaseModel):
    display_url: str
    method: str
    interval_seconds: int
    timeout_ms: int
    retry_attempts: int
    expected_status: list[list[int]]
    validation: dict[str, Any] | None
    latency_threshold_ms: int | None
    failure_threshold: int
    recovery_threshold: int
    tls_warn_days: int
    header_count: int
    tags: list[str]


class MonitorOut(BaseModel):
    id: uuid.UUID
    name: str
    project_id: uuid.UUID
    hostname: str
    lifecycle: str
    paused_reason: str | None
    attention_reason: str | None
    health_state: str
    latest: LatestOut | None
    version: int
    config: MonitorConfigOut | None = None


class MonitorEditOut(BaseModel):
    """Edit form for MON.update holders: the decrypted URL, never the header values."""

    url: str
    monitor: MonitorOut


class MeasurementOut(BaseModel):
    id: uuid.UUID
    trigger: str
    scheduled_for: datetime | None
    observed_at: datetime
    result: str
    failure_category: str | None
    http_status: int | None
    elapsed_ms: int | None
    attempt_count: int
    tls_not_after: datetime | None


def _latest(measurement: Measurement | None) -> LatestOut | None:
    if measurement is None:
        return None
    return LatestOut.model_validate(measurement, from_attributes=True)


def _config(monitor: Monitor) -> MonitorConfigOut:
    return MonitorConfigOut(
        display_url=monitor.display_url,
        method=monitor.method,
        interval_seconds=monitor.interval_seconds,
        timeout_ms=monitor.timeout_ms,
        retry_attempts=monitor.retry_attempts,
        expected_status=monitor.expected_status_json,
        validation=monitor.validation_json,
        latency_threshold_ms=monitor.latency_threshold_ms,
        failure_threshold=monitor.failure_threshold,
        recovery_threshold=monitor.recovery_threshold,
        tls_warn_days=monitor.tls_warn_days,
        header_count=monitor.header_count,
        tags=monitor.tags_json,
    )


def _out(view: monitors.MonitorView) -> MonitorOut:
    m = view.monitor
    return MonitorOut(
        id=m.id,
        name=m.name,
        project_id=m.project_id,
        hostname=m.hostname,
        lifecycle=m.lifecycle,
        paused_reason=m.paused_reason,
        attention_reason=m.attention_reason,
        health_state=view.health_state,
        latest=_latest(view.latest),
        version=m.version,
        config=_config(m) if view.can_view_config else None,
    )


async def _view(db: DbSession, ctx: OrgContext, monitor_id: uuid.UUID) -> MonitorOut:
    return _out(await monitors.get_monitor(db, ctx, monitor_id))


@router.get("", response_model=list[MonitorOut])
async def list_monitors(
    db: DbSession, ctx: Annotated[OrgContext, Ctx("MON.view")], include_archived: bool = False
) -> list[MonitorOut]:
    return [
        _out(v) for v in await monitors.list_monitors(db, ctx, include_archived=include_archived)
    ]


@router.post("", response_model=MonitorOut, status_code=status.HTTP_201_CREATED)
async def create_monitor(
    body: MonitorIn, db: DbSession, box: Box, ctx: Annotated[OrgContext, Ctx("MON.create")]
) -> MonitorOut:
    monitor = await monitors.create_monitor(db, ctx, box, body.to_input())
    return await _view(db, ctx, monitor.id)


@router.get("/{monitor_id}", response_model=MonitorOut)
async def get_monitor(
    monitor_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("MON.view")]
) -> MonitorOut:
    return await _view(db, ctx, monitor_id)


@router.get("/{monitor_id}/edit", response_model=MonitorEditOut)
async def get_monitor_for_edit(
    monitor_id: uuid.UUID, db: DbSession, box: Box, ctx: Annotated[OrgContext, Ctx("MON.update")]
) -> MonitorEditOut:
    _monitor, url = await monitors.get_for_edit(db, ctx, box, monitor_id)
    return MonitorEditOut(url=url, monitor=await _view(db, ctx, monitor_id))


@router.patch("/{monitor_id}", response_model=MonitorOut)
async def update_monitor(
    monitor_id: uuid.UUID,
    body: MonitorUpdate,
    db: DbSession,
    box: Box,
    ctx: Annotated[OrgContext, Ctx("MON.update")],
) -> MonitorOut:
    await monitors.update_monitor(db, ctx, box, monitor_id, body.version, body.to_input())
    return await _view(db, ctx, monitor_id)


@router.put("/{monitor_id}/headers", response_model=MonitorOut)
async def set_headers(
    monitor_id: uuid.UUID,
    body: HeadersIn,
    db: DbSession,
    box: Box,
    ctx: Annotated[OrgContext, Ctx("MON.secret.write")],
) -> MonitorOut:
    pairs = [(h.name, h.value) for h in body.headers]
    await monitors.set_headers(db, ctx, box, monitor_id, pairs)
    return await _view(db, ctx, monitor_id)


@router.post("/{monitor_id}/pause", response_model=MonitorOut)
async def pause_monitor(
    monitor_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("MON.pause")]
) -> MonitorOut:
    await monitors.pause(db, ctx, monitor_id)
    return await _view(db, ctx, monitor_id)


@router.post("/{monitor_id}/resume", response_model=MonitorOut)
async def resume_monitor(
    monitor_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("MON.resume")]
) -> MonitorOut:
    await monitors.resume(db, ctx, monitor_id)
    return await _view(db, ctx, monitor_id)


@router.post("/{monitor_id}/archive", response_model=MonitorOut)
async def archive_monitor(
    monitor_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("MON.archive")]
) -> MonitorOut:
    await monitors.archive(db, ctx, monitor_id)
    return await _view(db, ctx, monitor_id)


@router.post("/{monitor_id}/unarchive", response_model=MonitorOut)
async def unarchive_monitor(
    monitor_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("MON.archive")]
) -> MonitorOut:
    await monitors.unarchive(db, ctx, monitor_id)
    return await _view(db, ctx, monitor_id)


@router.post("/{monitor_id}/check-now", status_code=status.HTTP_202_ACCEPTED)
async def check_now(
    monitor_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("MON.check_now")]
) -> dict[str, str]:
    await monitors.request_check(db, ctx, monitor_id)
    return {"status": "queued"}


@router.get("/{monitor_id}/measurements", response_model=list[MeasurementOut])
async def list_measurements(
    monitor_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("MON.view")],
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[MeasurementOut]:
    rows = await monitors.list_measurements(
        db, ctx, monitor_id, since=since, until=until, limit=limit
    )
    return [MeasurementOut.model_validate(r, from_attributes=True) for r in rows]
