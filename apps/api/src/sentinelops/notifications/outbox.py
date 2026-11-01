"""Transactional outbox writes (FR-NTF-002/003, ADR-013, IC-13).

Rows are inserted in the caller's transaction, so an incident transition and its notifications
commit or roll back together. ``dedupe_key`` is deterministic (``incident_id:event:channel_id``)
and unique per organization, so replays and overlapping routes never enqueue twice. This module
never touches secrets (the platform plane uses it to cancel on suspension).
"""

import uuid
from datetime import datetime

from sqlalchemy import or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.catalog.models import Monitor
from sentinelops.db.base import new_id
from sentinelops.incidents.models import EventType, Incident, IncidentEvent, IncidentType
from sentinelops.notifications.models import (
    NotificationChannel,
    NotificationOutbox,
    NotificationRoute,
    NotifyEvent,
    OutboxState,
)

# Cancellation reasons recorded on outbox rows (FR-NTF-005, FR-PLT-004).
ORG_SUSPENDED_REASON = "ORG_SUSPENDED"
CHANNEL_DISABLED_REASON = "CHANNEL_DISABLED"


def notify_event_for(incident: Incident, event: IncidentEvent) -> str | None:
    """Timeline events that notify (FR-NTF-002); assignments and notes do not."""
    if event.event_type == EventType.OPENED:
        if incident.type == IncidentType.TLS_EXPIRY:
            return NotifyEvent.TLS_EXPIRY_WARNING
        return NotifyEvent.INCIDENT_OPENED
    if event.event_type == EventType.ACKNOWLEDGED:
        return NotifyEvent.INCIDENT_ACKNOWLEDGED
    if event.event_type == EventType.RESOLVED:
        return NotifyEvent.INCIDENT_RESOLVED
    return None


async def routed_channels(
    db: AsyncSession, organization_id: uuid.UUID, monitor_id: uuid.UUID, event_type: str
) -> list[uuid.UUID]:
    """Enabled channels with an enabled route for this event covering the monitor."""
    project_id = await db.scalar(
        select(Monitor.project_id).where(
            Monitor.organization_id == organization_id, Monitor.id == monitor_id
        )
    )
    rows = await db.scalars(
        select(NotificationRoute.channel_id)
        .join(
            NotificationChannel,
            (NotificationChannel.organization_id == NotificationRoute.organization_id)
            & (NotificationChannel.id == NotificationRoute.channel_id),
        )
        .where(
            NotificationRoute.organization_id == organization_id,
            NotificationRoute.enabled.is_(True),
            NotificationChannel.enabled.is_(True),
            NotificationRoute.event_types_json.contains([event_type]),
            or_(
                (NotificationRoute.project_id.is_(None)) & (NotificationRoute.monitor_id.is_(None)),
                NotificationRoute.project_id == project_id,
                NotificationRoute.monitor_id == monitor_id,
            ),
        )
        .distinct()
    )
    return sorted(rows)


async def _insert(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    channel_id: uuid.UUID,
    event_type: str,
    dedupe_key: str,
    now: datetime,
    incident_id: uuid.UUID | None = None,
    incident_event_id: uuid.UUID | None = None,
    monitor_id: uuid.UUID | None = None,
) -> bool:
    inserted = await db.scalar(
        insert(NotificationOutbox)
        .values(
            id=new_id(),
            organization_id=organization_id,
            incident_id=incident_id,
            incident_event_id=incident_event_id,
            monitor_id=monitor_id,
            channel_id=channel_id,
            event_type=event_type,
            dedupe_key=dedupe_key,
            state=OutboxState.PENDING,
            attempts=0,
            next_attempt_at=now,
            created_at=now,
        )
        .on_conflict_do_nothing(index_elements=["organization_id", "dedupe_key"])
        .returning(NotificationOutbox.id)
    )
    return inserted is not None


async def enqueue_incident_event(db: AsyncSession, incident: Incident, event: IncidentEvent) -> int:
    event_type = notify_event_for(incident, event)
    if event_type is None:
        return 0
    count = 0
    for channel_id in await routed_channels(
        db, incident.organization_id, incident.monitor_id, event_type
    ):
        count += await _insert(
            db,
            organization_id=incident.organization_id,
            channel_id=channel_id,
            event_type=event_type,
            dedupe_key=f"{incident.id}:{event_type}:{channel_id}",
            now=event.created_at,
            incident_id=incident.id,
            incident_event_id=event.id,
            monitor_id=incident.monitor_id,
        )
    return count


async def enqueue_auto_paused(
    db: AsyncSession, organization_id: uuid.UUID, monitor_id: uuid.UUID, generation: int
) -> int:
    """One notice per auto-pause; the new schedule generation identifies the occurrence."""
    now = clock.now()
    count = 0
    for channel_id in await routed_channels(
        db, organization_id, monitor_id, NotifyEvent.MONITOR_AUTO_PAUSED
    ):
        count += await _insert(
            db,
            organization_id=organization_id,
            channel_id=channel_id,
            event_type=NotifyEvent.MONITOR_AUTO_PAUSED,
            dedupe_key=f"{monitor_id}:{NotifyEvent.MONITOR_AUTO_PAUSED}:{generation}:{channel_id}",
            now=now,
            monitor_id=monitor_id,
        )
    return count


async def enqueue_test(db: AsyncSession, channel: NotificationChannel) -> None:
    now = clock.now()
    await _insert(
        db,
        organization_id=channel.organization_id,
        channel_id=channel.id,
        event_type=NotifyEvent.CHANNEL_TEST,
        dedupe_key=f"test:{channel.id}:{new_id()}",
        now=now,
    )


async def cancel_pending(
    db: AsyncSession,
    organization_id: uuid.UUID,
    reason: str,
    *,
    channel_id: uuid.UUID | None = None,
) -> int:
    """Cancel undelivered items (suspension, disabled channel). Leased items are re-validated
    by the notifier immediately before sending. No commit."""
    stmt = (
        update(NotificationOutbox)
        .where(
            NotificationOutbox.organization_id == organization_id,
            NotificationOutbox.state == OutboxState.PENDING,
        )
        .values(state=OutboxState.CANCELLED, cancel_reason=reason)
        .execution_options(synchronize_session=False)
    )
    if channel_id is not None:
        stmt = stmt.where(NotificationOutbox.channel_id == channel_id)
    result = await db.execute(stmt)
    return int(getattr(result, "rowcount", 0) or 0)
