"""Incident timeline events: the single write path for incident changes (ADR-013).

Every incident change appends exactly one ``incident_event`` in the caller's transaction, so an
incident transition and its event commit or roll back together. Lifecycle events (OPENED,
ACKNOWLEDGED, RESOLVED) are unique per incident in the database, which makes replays no-ops.
Notifiable events are fanned out to ``notification_outbox`` here, in the same transaction
(G5); the notifier process delivers them after commit.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.db.base import new_id
from sentinelops.incidents.models import EventType, Incident, IncidentEvent
from sentinelops.notifications.outbox import enqueue_incident_event
from sentinelops.realtime.publish import publish

# FR-NTF-002 events; ASSIGNED/UNASSIGNED/COMMENTED are timeline-only updates.
NOTIFIABLE = frozenset({EventType.OPENED, EventType.ACKNOWLEDGED, EventType.RESOLVED})


async def emit(
    db: AsyncSession,
    incident: Incident,
    event_type: str,
    *,
    at: datetime,
    actor_user_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
) -> IncidentEvent:
    event = IncidentEvent(
        id=new_id(),
        organization_id=incident.organization_id,
        incident_id=incident.id,
        actor_kind="USER" if actor_user_id else "SYSTEM",
        actor_user_id=actor_user_id,
        event_type=event_type,
        details_sanitized_json=details or {},
        created_at=at,
    )
    db.add(event)
    incident.last_event_at = at
    if event_type in NOTIFIABLE:
        await db.flush()  # the outbox references the incident and event rows
        await enqueue_incident_event(db, incident, event)
    await publish(
        db,
        incident.organization_id,
        f"incident.{event_type.lower()}",
        incident_id=incident.id,
        monitor_id=incident.monitor_id,
        type=incident.type,
        severity=incident.severity,
        status=incident.status,
    )
    return event
