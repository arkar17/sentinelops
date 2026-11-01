"""Monitor management (FR-MON-002/008/009/013/014/015). All queries are organization-scoped.

The URL and custom headers are sealed with SecretBox bound to (organization, monitor, field).
Headers are write-only: no API returns their names or values, only a count.
"""

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.authz.matrix import allows
from sentinelops.catalog.eligibility import (
    DOMAIN_UNVERIFIED,
    covering_domain,
    reschedule,
    reset_health,
)
from sentinelops.catalog.models import Monitor, MonitorLifecycle, Project
from sentinelops.db.base import new_id
from sentinelops.errors import AppError
from sentinelops.measurements.models import Measurement
from sentinelops.platform.models import PlatformSettings
from sentinelops.probe_policy.urls import ParsedTarget, parse_target
from sentinelops.probes.http.engine import parse_json_path
from sentinelops.scheduler.models import MonitorHealth, MonitorSchedule
from sentinelops.secrets.cipher import SecretBinding, SecretBox
from sentinelops.tenancy.context import OrgContext
from sentinelops.tenancy.limits import effective_limits
from sentinelops.tenancy.locks import lock_organization

_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
_DENIED_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "upgrade",
        "te",
        "trailer",
        "keep-alive",
        "expect",
        "user-agent",
        "accept-encoding",
        "forwarded",
        "x-real-ip",
    }
)
_DENIED_HEADER_PREFIXES = ("proxy-", "x-forwarded-")
MAX_HEADER_VALUE = 2048


def _error(code: str, message: str, status: int = 422) -> AppError:
    return AppError(status, code, message)


# --- input validation -------------------------------------------------------------------------


def parse_expected_status(values: list[str | int]) -> list[list[int]]:
    ranges: list[list[int]] = []
    for value in values or ["200-299"]:
        text = str(value).strip()
        low_text, _, high_text = text.partition("-")
        try:
            low, high = int(low_text), int(high_text or low_text)
        except ValueError as exc:
            raise _error("INVALID_EXPECTED_STATUS", f"Invalid status {text!r}") from exc
        if not 100 <= low <= high <= 599:
            raise _error("INVALID_EXPECTED_STATUS", "Status codes must be within 100-599")
        ranges.append([low, high])
    if len(ranges) > 20:
        raise _error("INVALID_EXPECTED_STATUS", "At most 20 status codes or ranges")
    return ranges


def validate_rule(rule: dict[str, Any] | None, method: str) -> dict[str, Any] | None:
    if rule is None:
        return None
    if method != "GET":
        raise _error("VALIDATION_NEEDS_GET", "Response validation requires the GET method")
    if rule.get("type") == "substring":
        value = rule.get("value")
        if not isinstance(value, str) or not 1 <= len(value) <= 200:
            raise _error("INVALID_VALIDATION", "Substring must be 1-200 characters")
        return {"type": "substring", "value": value}
    if rule.get("type") == "json_path":
        path = rule.get("path")
        expected = rule.get("equals")
        if not isinstance(path, str):
            raise _error("INVALID_VALIDATION", "A JSON path is required")
        try:
            parse_json_path(path)
        except ValueError as exc:
            raise _error("INVALID_VALIDATION", str(exc)) from exc
        if not isinstance(expected, str | int | float | bool) and expected is not None:
            raise _error(
                "INVALID_VALIDATION", "Expected value must be a string, number, boolean or null"
            )
        if len(json.dumps(expected)) > 200:
            raise _error("INVALID_VALIDATION", "Expected value is too long")
        return {"type": "json_path", "path": path, "equals": expected}
    raise _error("INVALID_VALIDATION", "Validation type must be substring or json_path")


def validate_headers(headers: list[tuple[str, str]], max_headers: int) -> list[tuple[str, str]]:
    if len(headers) > max_headers:
        raise _error("TOO_MANY_HEADERS", f"At most {max_headers} custom headers are allowed")
    seen: set[str] = set()
    for name, value in headers:
        lowered = name.lower()
        if not _HEADER_NAME.fullmatch(name):
            raise _error(
                "INVALID_HEADER", "Header names must be HTTP tokens of up to 64 characters"
            )
        if lowered in _DENIED_HEADERS or lowered.startswith(_DENIED_HEADER_PREFIXES):
            raise _error("HEADER_NOT_ALLOWED", f"The {name} header cannot be set")
        if lowered in seen:
            raise _error("INVALID_HEADER", "Each header may appear once")
        seen.add(lowered)
        if len(value) > MAX_HEADER_VALUE or any(
            (ord(c) < 0x20 and c != "\t") or ord(c) == 0x7F for c in value
        ):
            raise _error(
                "INVALID_HEADER", "Header values must be printable and at most 2048 characters"
            )
    return headers


# --- helpers ----------------------------------------------------------------------------------


def _binding(monitor: Monitor, field: str) -> SecretBinding:
    return SecretBinding(monitor.organization_id, "monitor", monitor.id, field)


def decrypt_url(box: SecretBox, monitor: Monitor) -> str:
    return box.open(monitor.url_key_id, monitor.url_ciphertext, _binding(monitor, "url"))


def decrypt_headers(box: SecretBox, monitor: Monitor) -> list[tuple[str, str]]:
    if monitor.header_ciphertext is None or monitor.header_key_id is None:
        return []
    pairs = json.loads(
        box.open(monitor.header_key_id, monitor.header_ciphertext, _binding(monitor, "headers"))
    )
    return [(str(name), str(value)) for name, value in pairs]


def _audit(
    db: AsyncSession, ctx: OrgContext, action: str, monitor_id: uuid.UUID, **details: Any
) -> None:
    record(
        db,
        action,
        scope="ORGANIZATION",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        actor_plane="ORG",
        entity_kind="monitor",
        entity_id=monitor_id,
        details=details or None,
    )


async def _platform(db: AsyncSession) -> PlatformSettings:
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        raise AppError(500, "SETTINGS_MISSING", "Platform settings are not initialized")
    return settings


async def _check_project(db: AsyncSession, ctx: OrgContext, project_id: uuid.UUID) -> None:
    exists = await db.scalar(
        select(Project.id).where(
            Project.organization_id == ctx.organization_id,
            Project.id == project_id,
            Project.archived_at.is_(None),
        )
    )
    if exists is None:
        raise _error("PROJECT_NOT_FOUND", "Choose an active project in this organization", 404)


async def _count_live(db: AsyncSession, organization_id: uuid.UUID) -> int:
    return int(
        await db.scalar(
            select(func.count())
            .select_from(Monitor)
            .where(
                Monitor.organization_id == organization_id,
                Monitor.lifecycle != MonitorLifecycle.ARCHIVED,
            )
        )
        or 0
    )


async def _enforce_limit(db: AsyncSession, ctx: OrgContext) -> None:
    """Caller holds the organization lock, so concurrent creates cannot overshoot (FR-MON-015)."""
    limit = (await effective_limits(db, ctx.organization_id)).max_monitors
    if await _count_live(db, ctx.organization_id) >= limit:
        raise _error("LIMIT_EXCEEDED", f"This organization may have at most {limit} monitors", 409)


async def _get(db: AsyncSession, ctx: OrgContext, monitor_id: uuid.UUID) -> Monitor:
    monitor = await db.scalar(
        select(Monitor)
        .where(Monitor.organization_id == ctx.organization_id, Monitor.id == monitor_id)
        .with_for_update()
    )
    if monitor is None:
        raise AppError(404, "NOT_FOUND", "Monitor not found")
    return monitor


@dataclass(frozen=True)
class MonitorInput:
    name: str
    project_id: uuid.UUID
    url: str
    method: str
    interval_seconds: int
    timeout_ms: int
    retry_attempts: int
    expected_status: list[str | int]
    validation: dict[str, Any] | None
    latency_threshold_ms: int | None
    failure_threshold: int
    recovery_threshold: int
    tls_warn_days: int
    tags: list[str]


async def _validate_config(
    db: AsyncSession, ctx: OrgContext, data: MonitorInput
) -> tuple[ParsedTarget, list[list[int]], dict[str, Any] | None]:
    platform = await _platform(db)
    limits = await effective_limits(db, ctx.organization_id)
    if data.interval_seconds < limits.min_interval_seconds:
        raise _error(
            "INTERVAL_TOO_SHORT", f"The minimum interval is {limits.min_interval_seconds} seconds"
        )
    if data.timeout_ms > platform.max_timeout_ms:
        raise _error("TIMEOUT_TOO_LONG", f"The maximum timeout is {platform.max_timeout_ms} ms")
    if data.retry_attempts > platform.max_retry_attempts:
        raise _error(
            "TOO_MANY_RETRIES", f"At most {platform.max_retry_attempts} retries are allowed"
        )
    await _check_project(db, ctx, data.project_id)
    return (
        parse_target(data.url),
        parse_expected_status(data.expected_status),
        validate_rule(data.validation, data.method),
    )


async def _apply_lifecycle_for_coverage(db: AsyncSession, monitor: Monitor, now: datetime) -> None:
    covered = await covering_domain(db, monitor.organization_id, monitor.hostname, now) is not None
    if monitor.lifecycle in (MonitorLifecycle.ACTIVE, MonitorLifecycle.DRAFT):
        monitor.lifecycle = MonitorLifecycle.ACTIVE if covered else MonitorLifecycle.DRAFT
        monitor.attention_reason = None if covered else DOMAIN_UNVERIFIED


# --- use cases --------------------------------------------------------------------------------


async def create_monitor(
    db: AsyncSession, ctx: OrgContext, box: SecretBox, data: MonitorInput
) -> Monitor:
    if await lock_organization(db, ctx.organization_id) is None:
        raise AppError(404, "NOT_FOUND", "Organization not found")
    await _enforce_limit(db, ctx)
    target, expected, rule = await _validate_config(db, ctx, data)
    now = clock.now()
    monitor = Monitor(
        id=new_id(),
        organization_id=ctx.organization_id,
        project_id=data.project_id,
        kind="HTTP",
        name=data.name,
        hostname=target.hostname,
        display_url=target.display_url,
        method=data.method,
        interval_seconds=data.interval_seconds,
        timeout_ms=data.timeout_ms,
        retry_attempts=data.retry_attempts,
        expected_status_json=expected,
        validation_json=rule,
        header_count=0,
        latency_threshold_ms=data.latency_threshold_ms,
        failure_threshold=data.failure_threshold,
        recovery_threshold=data.recovery_threshold,
        tls_warn_days=data.tls_warn_days,
        tags_json=data.tags,
        lifecycle=MonitorLifecycle.DRAFT,
        created_by=ctx.user_id,
        created_at=now,
        updated_at=now,
    )
    sealed = box.seal(target.url, _binding(monitor, "url"))
    monitor.url_ciphertext, monitor.url_key_id = sealed.ciphertext, sealed.key_id
    await _apply_lifecycle_for_coverage(db, monitor, now)
    db.add(monitor)
    await db.flush()
    db.add(
        MonitorSchedule(
            monitor_id=monitor.id,
            organization_id=ctx.organization_id,
            next_due_at=now,
            generation=1,
            missed_slots=0,
        )
    )
    db.add(
        MonitorHealth(monitor_id=monitor.id, organization_id=ctx.organization_id, state="UNKNOWN")
    )
    await db.flush()
    await reschedule(db, monitor, now=now, run_soon=True)
    _audit(db, ctx, AuditAction.MONITOR_CREATED, monitor.id, lifecycle=monitor.lifecycle)
    await db.commit()
    return monitor


async def update_monitor(
    db: AsyncSession,
    ctx: OrgContext,
    box: SecretBox,
    monitor_id: uuid.UUID,
    version: int,
    data: MonitorInput,
) -> Monitor:
    monitor = await _get(db, ctx, monitor_id)
    if monitor.version != version:
        raise _error("VERSION_CONFLICT", "The monitor was changed; reload", 409)
    if monitor.lifecycle == MonitorLifecycle.ARCHIVED:
        raise _error("MONITOR_ARCHIVED", "Unarchive the monitor before editing it", 409)
    target, expected, rule = await _validate_config(db, ctx, data)
    now = clock.now()
    monitor.name = data.name
    monitor.project_id = data.project_id
    monitor.hostname = target.hostname
    monitor.display_url = target.display_url
    sealed = box.seal(target.url, _binding(monitor, "url"))
    monitor.url_ciphertext, monitor.url_key_id = sealed.ciphertext, sealed.key_id
    monitor.method = data.method
    monitor.interval_seconds = data.interval_seconds
    monitor.timeout_ms = data.timeout_ms
    monitor.retry_attempts = data.retry_attempts
    monitor.expected_status_json = expected
    monitor.validation_json = rule
    monitor.latency_threshold_ms = data.latency_threshold_ms
    monitor.failure_threshold = data.failure_threshold
    monitor.recovery_threshold = data.recovery_threshold
    monitor.tls_warn_days = data.tls_warn_days
    monitor.tags_json = data.tags
    monitor.version += 1
    await _apply_lifecycle_for_coverage(db, monitor, now)
    await reset_health(db, ctx.organization_id, monitor.id)
    await reschedule(db, monitor, now=now, run_soon=True)
    _audit(db, ctx, AuditAction.MONITOR_UPDATED, monitor.id)
    await db.commit()
    return monitor


async def set_headers(
    db: AsyncSession,
    ctx: OrgContext,
    box: SecretBox,
    monitor_id: uuid.UUID,
    headers: list[tuple[str, str]],
) -> Monitor:
    monitor = await _get(db, ctx, monitor_id)
    platform = await _platform(db)
    validate_headers(headers, min(platform.max_custom_headers, 5))
    if headers:
        sealed = box.seal(json.dumps(headers), _binding(monitor, "headers"))
        monitor.header_ciphertext, monitor.header_key_id = sealed.ciphertext, sealed.key_id
    else:
        monitor.header_ciphertext = monitor.header_key_id = None
    monitor.header_count = len(headers)
    monitor.version += 1
    await reschedule(db, monitor, now=clock.now(), run_soon=False)
    _audit(db, ctx, AuditAction.MONITOR_HEADERS_CHANGED, monitor.id, header_count=len(headers))
    await db.commit()
    return monitor


async def pause(db: AsyncSession, ctx: OrgContext, monitor_id: uuid.UUID) -> Monitor:
    monitor = await _get(db, ctx, monitor_id)
    if monitor.lifecycle not in (MonitorLifecycle.ACTIVE, MonitorLifecycle.DRAFT):
        raise _error("INVALID_TRANSITION", f"A {monitor.lifecycle} monitor cannot be paused", 409)
    monitor.lifecycle = MonitorLifecycle.PAUSED
    monitor.paused_reason = "USER"
    monitor.version += 1
    await reschedule(db, monitor, now=clock.now(), run_soon=False)
    _audit(db, ctx, AuditAction.MONITOR_PAUSED, monitor.id)
    await db.commit()
    return monitor


async def resume(db: AsyncSession, ctx: OrgContext, monitor_id: uuid.UUID) -> Monitor:
    """PAUSED or DRAFT → ACTIVE when covered, else DRAFT (eligibility re-checked now)."""
    monitor = await _get(db, ctx, monitor_id)
    if monitor.lifecycle not in (MonitorLifecycle.PAUSED, MonitorLifecycle.DRAFT):
        raise _error("INVALID_TRANSITION", f"A {monitor.lifecycle} monitor cannot be resumed", 409)
    now = clock.now()
    monitor.lifecycle = MonitorLifecycle.DRAFT
    monitor.paused_reason = None
    await _apply_lifecycle_for_coverage(db, monitor, now)
    monitor.version += 1
    await reset_health(db, ctx.organization_id, monitor.id)
    await reschedule(db, monitor, now=now, run_soon=True)
    _audit(db, ctx, AuditAction.MONITOR_RESUMED, monitor.id, lifecycle=monitor.lifecycle)
    await db.commit()
    return monitor


async def archive(db: AsyncSession, ctx: OrgContext, monitor_id: uuid.UUID) -> Monitor:
    monitor = await _get(db, ctx, monitor_id)
    if monitor.lifecycle != MonitorLifecycle.ARCHIVED:
        monitor.lifecycle = MonitorLifecycle.ARCHIVED
        monitor.paused_reason = None
        monitor.version += 1
        await reschedule(db, monitor, now=clock.now(), run_soon=False)
        _audit(db, ctx, AuditAction.MONITOR_ARCHIVED, monitor.id)
        await db.commit()
    return monitor


async def unarchive(db: AsyncSession, ctx: OrgContext, monitor_id: uuid.UUID) -> Monitor:
    if await lock_organization(db, ctx.organization_id) is None:
        raise AppError(404, "NOT_FOUND", "Organization not found")
    monitor = await _get(db, ctx, monitor_id)
    if monitor.lifecycle != MonitorLifecycle.ARCHIVED:
        return monitor
    await _enforce_limit(db, ctx)
    monitor.lifecycle = MonitorLifecycle.PAUSED
    monitor.paused_reason = "USER"
    monitor.version += 1
    _audit(db, ctx, AuditAction.MONITOR_UNARCHIVED, monitor.id)
    await db.commit()
    return monitor


async def request_check(db: AsyncSession, ctx: OrgContext, monitor_id: uuid.UUID) -> None:
    """FR-MON-008: rate-limited manual check through the same worker path."""
    monitor = await _get(db, ctx, monitor_id)
    if monitor.lifecycle != MonitorLifecycle.ACTIVE:
        raise _error("MONITOR_NOT_ACTIVE", "Only active monitors can be checked", 409)
    platform = await _platform(db)
    now = clock.now()
    schedule = await db.get(MonitorSchedule, monitor.id, with_for_update=True)
    if schedule is None:
        raise AppError(500, "SCHEDULE_MISSING", "Monitor schedule is missing")
    last = schedule.last_manual_check_requested_at
    if last is not None and now - last < timedelta(seconds=platform.check_now_per_monitor_seconds):
        raise _error(
            "CHECK_NOW_RATE_LIMITED", "This monitor was checked moments ago; try again shortly", 429
        )
    hour_ago = now - timedelta(hours=1)
    recent = await db.scalar(
        select(func.count())
        .select_from(MonitorSchedule)
        .where(
            MonitorSchedule.organization_id == ctx.organization_id,
            MonitorSchedule.last_manual_check_requested_at > hour_ago,
        )
    )
    manual_runs = await db.scalar(
        select(func.count())
        .select_from(Measurement)
        .where(
            Measurement.organization_id == ctx.organization_id,
            Measurement.trigger == "MANUAL",
            Measurement.observed_at > hour_ago,
        )
    )
    if max(int(recent or 0), int(manual_runs or 0)) >= platform.check_now_per_org_hour:
        raise _error(
            "CHECK_NOW_RATE_LIMITED",
            "This organization's hourly manual check limit is reached",
            429,
        )
    schedule.manual_check_requested_at = now
    schedule.last_manual_check_requested_at = now
    _audit(db, ctx, AuditAction.MONITOR_CHECK_REQUESTED, monitor.id)
    await db.commit()


# --- reads ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class MonitorView:
    monitor: Monitor
    health_state: str
    latest: Measurement | None
    can_view_config: bool


async def _latest(
    db: AsyncSession, ctx: OrgContext, monitor_ids: list[uuid.UUID]
) -> dict[uuid.UUID, Measurement]:
    if not monitor_ids:
        return {}
    rows = await db.scalars(
        select(Measurement)
        .where(
            Measurement.organization_id == ctx.organization_id,
            Measurement.monitor_id.in_(monitor_ids),
        )
        .ext(distinct_on(Measurement.monitor_id))
        .order_by(Measurement.monitor_id, Measurement.observed_at.desc())
    )
    return {m.monitor_id: m for m in rows}


async def list_monitors(
    db: AsyncSession, ctx: OrgContext, *, include_archived: bool
) -> list[MonitorView]:
    stmt = (
        select(Monitor, MonitorHealth.state)
        .join(MonitorHealth, MonitorHealth.monitor_id == Monitor.id)
        .where(Monitor.organization_id == ctx.organization_id)
        .order_by(func.lower(Monitor.name))
    )
    if not include_archived:
        stmt = stmt.where(Monitor.lifecycle != MonitorLifecycle.ARCHIVED)
    rows = list(await db.execute(stmt))
    latest = await _latest(db, ctx, [m.id for m, _ in rows])
    config = allows(ctx.role, "MON.view_config")
    return [MonitorView(m, state, latest.get(m.id), config) for m, state in rows]


async def get_monitor(db: AsyncSession, ctx: OrgContext, monitor_id: uuid.UUID) -> MonitorView:
    row = (
        await db.execute(
            select(Monitor, MonitorHealth.state)
            .join(MonitorHealth, MonitorHealth.monitor_id == Monitor.id)
            .where(Monitor.organization_id == ctx.organization_id, Monitor.id == monitor_id)
        )
    ).one_or_none()
    if row is None:
        raise AppError(404, "NOT_FOUND", "Monitor not found")
    monitor, state = row[0], row[1]
    latest = await _latest(db, ctx, [monitor.id])
    return MonitorView(monitor, state, latest.get(monitor.id), allows(ctx.role, "MON.view_config"))


async def get_for_edit(
    db: AsyncSession, ctx: OrgContext, box: SecretBox, monitor_id: uuid.UUID
) -> tuple[Monitor, str]:
    """MON.update holders see the decrypted URL in the edit form only (PERMISSION_MATRIX §5)."""
    monitor = await db.scalar(
        select(Monitor).where(
            Monitor.organization_id == ctx.organization_id, Monitor.id == monitor_id
        )
    )
    if monitor is None:
        raise AppError(404, "NOT_FOUND", "Monitor not found")
    return monitor, decrypt_url(box, monitor)


MAX_HISTORY = timedelta(days=30)  # NFR-006 raw retention window
MAX_HISTORY_ROWS = 500


async def list_measurements(
    db: AsyncSession,
    ctx: OrgContext,
    monitor_id: uuid.UUID,
    *,
    since: datetime | None,
    until: datetime | None,
    limit: int,
) -> list[Measurement]:
    exists = await db.scalar(
        select(Monitor.id).where(
            Monitor.organization_id == ctx.organization_id, Monitor.id == monitor_id
        )
    )
    if exists is None:
        raise AppError(404, "NOT_FOUND", "Monitor not found")
    now = clock.now()
    floor = now - MAX_HISTORY
    start = max(since or now - timedelta(hours=24), floor)
    end = until or now
    return list(
        await db.scalars(
            select(Measurement)
            .where(
                Measurement.organization_id == ctx.organization_id,
                Measurement.monitor_id == monitor_id,
                Measurement.observed_at >= start,
                Measurement.observed_at <= end,
            )
            .order_by(Measurement.observed_at.desc())
            .limit(min(limit, MAX_HISTORY_ROWS))
        )
    )
