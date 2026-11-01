"""Organization dashboard (RPT.dashboard), reports (RPT.view) and CSV export (RPT.export).

Responses and exports contain aggregate figures, display names and hosts only: no URLs, query
strings, headers, secrets or raw response content. Exports are streamed and never stored.
"""

import csv
import io
import uuid
from collections.abc import AsyncIterator, Iterable
from datetime import date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select

from sentinelops import clock
from sentinelops.db.session import DbSession
from sentinelops.errors import AppError
from sentinelops.measurements import reports
from sentinelops.measurements.dashboard import build_dashboard
from sentinelops.tenancy.context import OrgContext, OrgPermission
from sentinelops.tenancy.models import Organization

router = APIRouter(prefix="/api/orgs/{org_id}", tags=["reports"])

Period = Literal["24h", "7d", "30d", "custom"]
CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def Ctx(action: str) -> Any:  # noqa: N802  # reads like a type in signatures
    return Depends(OrgPermission(action))


class StatsOut(BaseModel):
    conclusive_samples: int
    available_samples: int
    failed_samples: int
    blocked_samples: int
    inconclusive_samples: int
    expected_samples: int
    missed_samples: int
    uptime_pct: float | None
    coverage_pct: float | None
    latency_p50_ms: int | None
    latency_p95_ms: int | None
    downtime_estimate_seconds: int
    outage_incident_seconds: int
    incidents_opened: int
    outage_incidents_opened: int
    tls_incidents_opened: int
    incidents_resolved: int
    mean_resolution_seconds: int | None
    mean_acknowledge_seconds: int | None


class WindowOut(BaseModel):
    period: str
    start: datetime
    end: datetime
    bucket: str
    timezone: str
    latency_method: Literal["exact", "approximate"]


class PointOut(BaseModel):
    bucket_start: datetime
    conclusive_samples: int
    available_samples: int
    uptime_pct: float | None
    latency_p50_ms: int | None
    latency_p95_ms: int | None


class MonitorRowOut(BaseModel):
    monitor_id: uuid.UUID
    name: str
    hostname: str
    project_id: uuid.UUID
    project_name: str
    lifecycle: str
    interval_seconds: int
    stats: StatsOut


class ReportOut(BaseModel):
    window: WindowOut
    summary: StatsOut
    median_resolution_seconds: int | None
    monitors: list[MonitorRowOut]
    total_monitors: int
    series: list[PointOut]


class AvailabilityOut(BaseModel):
    monitor_id: uuid.UUID
    periods: dict[str, StatsOut]


class TlsOut(BaseModel):
    monitor_id: uuid.UUID
    monitor_name: str
    hostname: str
    expires_at: datetime
    days_remaining: int
    warn_days: int


class CheckOut(BaseModel):
    monitor_id: uuid.UUID
    monitor_name: str
    result: str
    failure_category: str | None
    http_status: int | None
    elapsed_ms: int | None
    trigger: str
    observed_at: datetime


class RecentIncidentOut(BaseModel):
    id: uuid.UUID
    monitor_id: uuid.UUID
    monitor_name: str
    type: str
    severity: str
    status: str
    title: str
    opened_at: datetime
    resolved_at: datetime | None


class DashboardOut(BaseModel):
    generated_at: datetime
    monitors_by_lifecycle: dict[str, int]
    health: dict[str, int]
    active_incidents_by_severity: dict[str, int]
    recent_incidents: list[RecentIncidentOut]
    results_24h: dict[str, int]
    summary_24h: StatsOut
    window_24h: WindowOut
    series_24h: list[PointOut]
    tls_expiring: list[TlsOut]
    recent_checks: list[CheckOut]


def _stats(s: reports.Stats) -> StatsOut:
    return StatsOut(
        conclusive_samples=s.conclusive,
        available_samples=s.available,
        failed_samples=s.failed,
        blocked_samples=s.blocked,
        inconclusive_samples=s.inconclusive,
        expected_samples=s.expected,
        missed_samples=s.missed,
        uptime_pct=s.uptime_pct,
        coverage_pct=s.coverage_pct,
        latency_p50_ms=s.p50_ms,
        latency_p95_ms=s.p95_ms,
        downtime_estimate_seconds=s.downtime_est_seconds,
        outage_incident_seconds=s.outage_seconds,
        incidents_opened=s.incidents_opened,
        outage_incidents_opened=s.outage_incidents_opened,
        tls_incidents_opened=s.tls_incidents_opened,
        incidents_resolved=s.incidents_resolved,
        mean_resolution_seconds=s.mean_resolution_seconds,
        mean_acknowledge_seconds=s.mean_ack_seconds,
    )


def _window(w: reports.Window) -> WindowOut:
    return WindowOut(
        period=w.period,
        start=w.start,
        end=w.end,
        bucket=w.bucket,
        timezone=w.timezone,
        latency_method="exact" if w.exact_latency else "approximate",
    )


def _points(points: list[reports.Point]) -> list[PointOut]:
    return [
        PointOut(
            bucket_start=p.bucket_start,
            conclusive_samples=p.conclusive,
            available_samples=p.available,
            uptime_pct=p.uptime_pct,
            latency_p50_ms=p.p50_ms,
            latency_p95_ms=p.p95_ms,
        )
        for p in points
    ]


async def _timezone(db: DbSession, ctx: OrgContext) -> str:
    tz = await db.scalar(
        select(Organization.timezone).where(Organization.id == ctx.organization_id)
    )
    return tz or "UTC"


async def _report(
    db: DbSession,
    ctx: OrgContext,
    *,
    period: str,
    date_from: date | None,
    date_to: date | None,
    project_id: uuid.UUID | None,
    include_archived: bool,
    limit: int | None,
    offset: int,
    with_series: bool,
) -> reports.Report:
    window = reports.resolve_window(
        period, date_from, date_to, await _timezone(db, ctx), clock.now()
    )
    monitors = await reports.select_monitors(
        db, ctx.organization_id, project_id=project_id, include_archived=include_archived
    )
    return await reports.build_report(
        db,
        ctx.organization_id,
        monitors,
        window,
        limit=limit,
        offset=offset,
        with_series=with_series,
    )


@router.get("/dashboard", response_model=DashboardOut)
async def dashboard(
    db: DbSession, ctx: Annotated[OrgContext, Ctx("RPT.dashboard")]
) -> DashboardOut:
    data = await build_dashboard(db, ctx.organization_id, await _timezone(db, ctx), clock.now())
    return DashboardOut(
        generated_at=data.generated_at,
        monitors_by_lifecycle=data.lifecycle_counts,
        health=data.health_counts,
        active_incidents_by_severity=data.active_incidents_by_severity,
        recent_incidents=[
            RecentIncidentOut(
                id=r.incident.id,
                monitor_id=r.incident.monitor_id,
                monitor_name=r.monitor_name,
                type=r.incident.type,
                severity=r.incident.severity,
                status=r.incident.status,
                title=r.incident.title_sanitized,
                opened_at=r.incident.opened_at,
                resolved_at=r.incident.resolved_at,
            )
            for r in data.recent_incidents
        ],
        results_24h=data.results_24h,
        summary_24h=_stats(data.report_24h.summary),
        window_24h=_window(data.report_24h.window),
        series_24h=_points(data.report_24h.series),
        tls_expiring=[TlsOut(**t.__dict__) for t in data.tls_expiring],
        recent_checks=[CheckOut(**c.__dict__) for c in data.recent_checks],
    )


@router.get("/reports", response_model=ReportOut)
async def report(
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("RPT.view")],
    period: Period = "24h",
    date_from: Annotated[date | None, Query(alias="from")] = None,
    date_to: Annotated[date | None, Query(alias="to")] = None,
    project_id: uuid.UUID | None = None,
    include_archived: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ReportOut:
    data = await _report(
        db,
        ctx,
        period=period,
        date_from=date_from,
        date_to=date_to,
        project_id=project_id,
        include_archived=include_archived,
        limit=limit,
        offset=offset,
        with_series=True,
    )
    return ReportOut(
        window=_window(data.window),
        summary=_stats(data.summary),
        median_resolution_seconds=data.median_resolution_seconds,
        monitors=[
            MonitorRowOut(
                monitor_id=m.monitor.id,
                name=m.monitor.name,
                hostname=m.monitor.hostname,
                project_id=m.monitor.project_id,
                project_name=m.monitor.project_name,
                lifecycle=m.monitor.lifecycle,
                interval_seconds=m.monitor.interval_seconds,
                stats=_stats(m.stats),
            )
            for m in data.monitors
        ],
        total_monitors=data.total_monitors,
        series=_points(data.series),
    )


@router.get("/reports/monitors/{monitor_id}/availability", response_model=AvailabilityOut)
async def monitor_availability(
    monitor_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("RPT.view")]
) -> AvailabilityOut:
    """FR-UI-002: uptime, coverage and latency for 24h/7d/30d."""
    monitors = await reports.select_monitors(db, ctx.organization_id, monitor_id=monitor_id)
    if not monitors:
        raise AppError(404, "NOT_FOUND", "Monitor not found")
    tz, now = await _timezone(db, ctx), clock.now()
    periods: dict[str, StatsOut] = {}
    for period in reports.PERIODS:
        window = reports.resolve_window(period, None, None, tz, now)
        data = await reports.build_report(
            db, ctx.organization_id, monitors, window, with_series=False
        )
        periods[period] = _stats(data.summary)
    return AvailabilityOut(monitor_id=monitor_id, periods=periods)


def csv_cell(value: object) -> str:
    """Neutralize spreadsheet formulas in text cells (CSV injection)."""
    if value is None:
        return ""
    text_ = str(value)
    if isinstance(value, str) and text_.startswith(CSV_INJECTION_PREFIXES):
        return "'" + text_
    return text_


EXPORT_COLUMNS = (
    "monitor",
    "host",
    "project",
    "lifecycle",
    "uptime_pct",
    "coverage_pct",
    "conclusive_samples",
    "available_samples",
    "failed_samples",
    "blocked_samples",
    "inconclusive_samples",
    "missed_samples",
    "latency_p50_ms",
    "latency_p95_ms",
    "downtime_estimate_seconds",
    "outage_incident_seconds",
    "incidents_opened",
    "incidents_resolved",
    "mean_resolution_seconds",
)


def _row(name: str, host: str, project: str, lifecycle: str, s: reports.Stats) -> list[object]:
    return [
        name,
        host,
        project,
        lifecycle,
        s.uptime_pct,
        s.coverage_pct,
        s.conclusive,
        s.available,
        s.failed,
        s.blocked,
        s.inconclusive,
        s.missed,
        s.p50_ms,
        s.p95_ms,
        s.downtime_est_seconds,
        s.outage_seconds,
        s.incidents_opened,
        s.incidents_resolved,
        s.mean_resolution_seconds,
    ]


async def _csv(rows: Iterable[list[object]]) -> AsyncIterator[str]:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for row in rows:
        writer.writerow([csv_cell(v) for v in row])
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate()


@router.get("/reports/export.csv")
async def export_csv(
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("RPT.export")],
    period: Period = "30d",
    date_from: Annotated[date | None, Query(alias="from")] = None,
    date_to: Annotated[date | None, Query(alias="to")] = None,
    project_id: uuid.UUID | None = None,
    include_archived: bool = False,
) -> StreamingResponse:
    data = await _report(
        db,
        ctx,
        period=period,
        date_from=date_from,
        date_to=date_to,
        project_id=project_id,
        include_archived=include_archived,
        limit=None,
        offset=0,
        with_series=False,
    )
    window = data.window
    rows: list[list[object]] = [
        ["window_start", window.start.isoformat(), "window_end", window.end.isoformat()],
        list(EXPORT_COLUMNS),
        *(
            _row(
                m.monitor.name,
                m.monitor.hostname,
                m.monitor.project_name,
                m.monitor.lifecycle,
                m.stats,
            )
            for m in data.monitors
        ),
        _row("All monitors", "", "", "", data.summary),
    ]
    filename = f"sentinelops-report-{ctx.slug}-{window.period}.csv"
    return StreamingResponse(
        _csv(rows),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
