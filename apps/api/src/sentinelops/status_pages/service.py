"""Status page management and the sanitized snapshot builder (FR-UI-004, ADR-016).

The snapshot is built from an explicit allowlist: page title, each selected monitor's public
display name, its public status and availability, and generic titles/times of OUTAGE incidents.
Never hostnames, URLs, monitor names, members, notes, assignees, evidence or TLS details.
The public endpoint serves only the stored snapshot of a published page of an ACTIVE
organization. Snapshots are rebuilt on every change and periodically by the worker.
"""

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import case, delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.catalog.models import Monitor, MonitorLifecycle
from sentinelops.db.base import new_id
from sentinelops.errors import AppError
from sentinelops.incidents.models import Incident, IncidentStatus, IncidentType
from sentinelops.measurements.models import Measurement
from sentinelops.scheduler.models import MonitorHealth
from sentinelops.status_pages.models import (
    SLUG_PATTERN,
    StatusPage,
    StatusPageMonitor,
    StatusPageSnapshot,
)
from sentinelops.tenancy.context import OrgContext
from sentinelops.tenancy.limits import effective_limits
from sentinelops.tenancy.locks import lock_organization
from sentinelops.tenancy.models import Organization, OrgStatus

MAX_MONITORS = 50
RECENT_INCIDENT_DAYS = 7
MAX_RECENT_INCIDENTS = 10
PUBLIC_INCIDENT_TITLE = "Service disruption"
_SLUG = re.compile(SLUG_PATTERN)
_PUBLIC_STATUS = {"UP": "OPERATIONAL", "DEGRADED": "DEGRADED", "DOWN": "OUTAGE"}
_SEVERITY = ["OPERATIONAL", "UNKNOWN", "DEGRADED", "OUTAGE"]


def _error(code: str, message: str, status: int = 422) -> AppError:
    return AppError(status, code, message)


def _not_found() -> AppError:
    return AppError(404, "NOT_FOUND", "Status page not found")


def clean_text(value: str, field: str, limit: int = 80) -> str:
    text = " ".join(value.split())
    if not 1 <= len(text) <= limit:
        raise _error("INVALID_TEXT", f"The {field} must be 1-{limit} characters")
    return text


def clean_slug(value: str) -> str:
    slug = value.strip().lower()
    if not _SLUG.fullmatch(slug):
        raise _error(
            "INVALID_SLUG", "Use 3-40 lowercase letters, digits or hyphens (not at the ends)"
        )
    return slug


@dataclass(frozen=True)
class PageMonitorInput:
    monitor_id: uuid.UUID
    public_display_name: str


@dataclass(frozen=True)
class PageView:
    page: StatusPage
    monitors: list[tuple[StatusPageMonitor, str]]  # (selection, private monitor name)


# --- snapshot ---------------------------------------------------------------------------------


async def _availability(
    db: AsyncSession, organization_id: uuid.UUID, monitor_ids: list[uuid.UUID], since: datetime
) -> dict[uuid.UUID, float]:
    if not monitor_ids:
        return {}
    rows = await db.execute(
        select(
            Measurement.monitor_id,
            func.count(),
            func.sum(case((Measurement.result.in_(["PASS", "SLOW"]), 1), else_=0)),
        )
        .where(
            Measurement.organization_id == organization_id,
            Measurement.monitor_id.in_(monitor_ids),
            Measurement.trigger == "SCHEDULED",
            Measurement.result.in_(["PASS", "SLOW", "FAIL"]),
            Measurement.observed_at >= since,
        )
        .group_by(Measurement.monitor_id)
    )
    return {
        monitor_id: round(100.0 * int(ok or 0) / int(total), 2)
        for monitor_id, total, ok in rows
        if total
    }


async def build_payload(db: AsyncSession, page: StatusPage, now: datetime) -> dict[str, Any]:
    rows = list(
        await db.execute(
            select(StatusPageMonitor, Monitor.lifecycle, MonitorHealth.state)
            .join(
                Monitor,
                (Monitor.organization_id == StatusPageMonitor.organization_id)
                & (Monitor.id == StatusPageMonitor.monitor_id),
            )
            .join(MonitorHealth, MonitorHealth.monitor_id == Monitor.id)
            .where(
                StatusPageMonitor.organization_id == page.organization_id,
                StatusPageMonitor.status_page_id == page.id,
                Monitor.lifecycle != MonitorLifecycle.ARCHIVED,
            )
            .order_by(StatusPageMonitor.sort_order, StatusPageMonitor.public_display_name)
        )
    )
    ids = [selection.monitor_id for selection, _, _ in rows]
    names = {selection.monitor_id: selection.public_display_name for selection, _, _ in rows}
    day = await _availability(db, page.organization_id, ids, now - timedelta(days=1))
    week = await _availability(db, page.organization_id, ids, now - timedelta(days=7))
    components: list[dict[str, Any]] = []
    for selection, lifecycle, health in rows:
        state = _PUBLIC_STATUS.get(health, "UNKNOWN") if lifecycle == "ACTIVE" else "UNKNOWN"
        components.append(
            {
                "name": selection.public_display_name,
                "status": state,
                "uptime_24h": day.get(selection.monitor_id),
                "uptime_7d": week.get(selection.monitor_id),
            }
        )
    incidents = list(
        await db.scalars(
            select(Incident)
            .where(
                Incident.organization_id == page.organization_id,
                Incident.monitor_id.in_(ids),
                Incident.type == IncidentType.OUTAGE,  # TLS warnings stay internal (IC-21)
                (Incident.status != IncidentStatus.RESOLVED)
                | (Incident.resolved_at >= now - timedelta(days=RECENT_INCIDENT_DAYS)),
            )
            .order_by(Incident.opened_at.desc())
        )
    )
    active = [
        {
            "title": PUBLIC_INCIDENT_TITLE,
            "component": names[i.monitor_id],
            "status": "INVESTIGATING" if i.status == IncidentStatus.OPEN else "ACKNOWLEDGED",
            "started_at": i.opened_at.isoformat(),
        }
        for i in incidents
        if i.status != IncidentStatus.RESOLVED
    ]
    recent = [
        {
            "title": PUBLIC_INCIDENT_TITLE,
            "component": names[i.monitor_id],
            "started_at": i.opened_at.isoformat(),
            "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
        }
        for i in incidents
        if i.status == IncidentStatus.RESOLVED
    ][:MAX_RECENT_INCIDENTS]
    statuses = [c["status"] for c in components] or ["UNKNOWN"]
    overall = max(statuses, key=_SEVERITY.index)
    return {
        "title": page.title,
        "generated_at": now.isoformat(),
        "overall": overall,
        "components": components,
        "active_incidents": active,
        "recent_incidents": recent,
    }


async def refresh_snapshot(db: AsyncSession, page: StatusPage, now: datetime) -> None:
    payload = await build_payload(db, page, now)
    await db.execute(
        insert(StatusPageSnapshot)
        .values(
            status_page_id=page.id,
            organization_id=page.organization_id,
            generated_at=now,
            safe_payload_json=payload,
        )
        .on_conflict_do_update(
            index_elements=["status_page_id"],
            set_={"generated_at": now, "safe_payload_json": payload},
        )
    )


async def refresh_published(db: AsyncSession, now: datetime) -> int:
    """Periodic rebuild of every published page of an ACTIVE organization. No commit."""
    pages = list(
        await db.scalars(
            select(StatusPage)
            .join(Organization, Organization.id == StatusPage.organization_id)
            .where(StatusPage.enabled.is_(True), Organization.status == OrgStatus.ACTIVE)
        )
    )
    for page in pages:
        await refresh_snapshot(db, page, now)
    return len(pages)


async def public_snapshot(db: AsyncSession, slug: str) -> dict[str, Any] | None:
    """Published page of an ACTIVE organization, or None (served as 404)."""
    if not _SLUG.fullmatch(slug):
        return None
    payload = await db.scalar(
        select(StatusPageSnapshot.safe_payload_json)
        .join(
            StatusPage,
            (StatusPage.organization_id == StatusPageSnapshot.organization_id)
            & (StatusPage.id == StatusPageSnapshot.status_page_id),
        )
        .join(Organization, Organization.id == StatusPage.organization_id)
        .where(
            StatusPage.public_slug == slug,
            StatusPage.enabled.is_(True),
            Organization.status == OrgStatus.ACTIVE,
        )
    )
    return dict(payload) if payload is not None else None


# --- management -------------------------------------------------------------------------------


def _audit(
    db: AsyncSession, ctx: OrgContext, action: str, page_id: uuid.UUID, **details: Any
) -> None:
    record(
        db,
        action,
        scope="ORGANIZATION",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        actor_plane="ORG",
        entity_kind="status_page",
        entity_id=page_id,
        details=details or None,
    )


async def _views(db: AsyncSession, ctx: OrgContext, pages: list[StatusPage]) -> list[PageView]:
    selections: dict[uuid.UUID, list[tuple[StatusPageMonitor, str]]] = {}
    if pages:
        rows = await db.execute(
            select(StatusPageMonitor, Monitor.name)
            .join(
                Monitor,
                (Monitor.organization_id == StatusPageMonitor.organization_id)
                & (Monitor.id == StatusPageMonitor.monitor_id),
            )
            .where(
                StatusPageMonitor.organization_id == ctx.organization_id,
                StatusPageMonitor.status_page_id.in_([p.id for p in pages]),
            )
            .order_by(StatusPageMonitor.sort_order)
        )
        for selection, name in rows:
            selections.setdefault(selection.status_page_id, []).append((selection, name))
    return [PageView(p, selections.get(p.id, [])) for p in pages]


async def list_pages(db: AsyncSession, ctx: OrgContext) -> list[PageView]:
    pages = list(
        await db.scalars(
            select(StatusPage)
            .where(StatusPage.organization_id == ctx.organization_id)
            .order_by(StatusPage.created_at)
        )
    )
    return await _views(db, ctx, pages)


async def _page(
    db: AsyncSession, ctx: OrgContext, page_id: uuid.UUID, *, lock: bool = False
) -> StatusPage:
    stmt = select(StatusPage).where(
        StatusPage.organization_id == ctx.organization_id, StatusPage.id == page_id
    )
    page = await db.scalar(stmt.with_for_update() if lock else stmt)
    if page is None:
        raise _not_found()
    return page


async def get_page(db: AsyncSession, ctx: OrgContext, page_id: uuid.UUID) -> PageView:
    return (await _views(db, ctx, [await _page(db, ctx, page_id)]))[0]


async def preview(db: AsyncSession, ctx: OrgContext, page_id: uuid.UUID) -> dict[str, Any]:
    return await build_payload(db, await _page(db, ctx, page_id), clock.now())


async def _set_monitors(
    db: AsyncSession, ctx: OrgContext, page: StatusPage, monitors: list[PageMonitorInput]
) -> None:
    if len(monitors) > MAX_MONITORS:
        raise _error("TOO_MANY_MONITORS", f"A page may show at most {MAX_MONITORS} monitors")
    ids = [m.monitor_id for m in monitors]
    if len(set(ids)) != len(ids):
        raise _error("DUPLICATE_MONITOR", "Each monitor may appear once")
    found = set(
        await db.scalars(
            select(Monitor.id).where(
                Monitor.organization_id == ctx.organization_id,
                Monitor.id.in_(ids),
                Monitor.lifecycle != MonitorLifecycle.ARCHIVED,
            )
        )
    )
    if found != set(ids):
        raise AppError(404, "MONITOR_NOT_FOUND", "Choose monitors of this organization")
    await db.execute(
        delete(StatusPageMonitor).where(
            StatusPageMonitor.organization_id == ctx.organization_id,
            StatusPageMonitor.status_page_id == page.id,
        )
    )
    for order, item in enumerate(monitors):
        db.add(
            StatusPageMonitor(
                organization_id=ctx.organization_id,
                status_page_id=page.id,
                monitor_id=item.monitor_id,
                public_display_name=clean_text(item.public_display_name, "public name"),
                sort_order=order,
            )
        )


async def _slug_safe(db: AsyncSession, *, commit: bool) -> None:
    """Flush or commit, turning a global slug collision into 409 SLUG_TAKEN."""
    try:
        await (db.commit() if commit else db.flush())
    except IntegrityError as exc:
        await db.rollback()
        if "uq_status_page_public_slug" in str(exc.orig):
            raise _error("SLUG_TAKEN", "This address is already in use", 409) from None
        raise


async def create_page(
    db: AsyncSession, ctx: OrgContext, *, title: str, slug: str, monitors: list[PageMonitorInput]
) -> StatusPage:
    clean_title, clean = clean_text(title, "title"), clean_slug(slug)
    if await lock_organization(db, ctx.organization_id) is None:
        raise AppError(404, "NOT_FOUND", "Organization not found")
    limit = (await effective_limits(db, ctx.organization_id)).max_status_pages
    count = await db.scalar(
        select(func.count())
        .select_from(StatusPage)
        .where(StatusPage.organization_id == ctx.organization_id)
    )
    if int(count or 0) >= limit:
        raise _error(
            "LIMIT_EXCEEDED", f"This organization may have at most {limit} status pages", 409
        )
    now = clock.now()
    page = StatusPage(
        id=new_id(),
        organization_id=ctx.organization_id,
        public_slug=clean,
        title=clean_title,
        enabled=False,  # unpublished until explicitly published (ADR-016)
        created_by=ctx.user_id,
        created_at=now,
        updated_at=now,
        version=1,
    )
    db.add(page)
    await _slug_safe(db, commit=False)
    await _set_monitors(db, ctx, page, monitors)
    _audit(db, ctx, AuditAction.STATUS_PAGE_CREATED, page.id, monitors=len(monitors))
    await _slug_safe(db, commit=True)
    return page


async def update_page(
    db: AsyncSession,
    ctx: OrgContext,
    page_id: uuid.UUID,
    *,
    version: int,
    title: str | None,
    slug: str | None,
    monitors: list[PageMonitorInput] | None,
) -> None:
    page = await _page(db, ctx, page_id, lock=True)
    if page.version != version:
        raise _error("VERSION_CONFLICT", "The page changed; reload and try again", 409)
    changed: list[str] = []
    if title is not None:
        page.title = clean_text(title, "title")
        changed.append("title")
    if slug is not None and clean_slug(slug) != page.public_slug:
        page.public_slug = clean_slug(slug)
        changed.append("slug")
    if monitors is not None:
        await _set_monitors(db, ctx, page, monitors)
        changed.append("monitors")
    page.version += 1
    await _slug_safe(db, commit=False)
    if page.enabled:
        await refresh_snapshot(db, page, clock.now())
    _audit(db, ctx, AuditAction.STATUS_PAGE_UPDATED, page.id, changed=changed)
    await _slug_safe(db, commit=True)


async def set_published(
    db: AsyncSession, ctx: OrgContext, page_id: uuid.UUID, *, published: bool
) -> None:
    page = await _page(db, ctx, page_id, lock=True)
    if page.enabled == published:
        return
    page.enabled = published
    page.version += 1
    if published:
        await refresh_snapshot(db, page, clock.now())
    action = AuditAction.STATUS_PAGE_PUBLISHED if published else AuditAction.STATUS_PAGE_UNPUBLISHED
    _audit(db, ctx, action, page.id)
    await db.commit()
