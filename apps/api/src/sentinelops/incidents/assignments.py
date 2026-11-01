"""Unassign incidents when a membership becomes inactive (FR-ORG-004, PERMISSION_MATRIX §4 rule 5).

Called by tenancy under the organization lock, in the membership change's transaction.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.incidents.events import emit
from sentinelops.incidents.models import EventType, Incident, IncidentStatus

MEMBERSHIP_INACTIVE = "MEMBERSHIP_INACTIVE"


async def unassign_member(db: AsyncSession, organization_id: uuid.UUID, user_id: uuid.UUID) -> int:
    """Unresolved incidents assigned to the member lose their assignee. No commit."""
    now = clock.now()
    incidents = list(
        await db.scalars(
            select(Incident)
            .where(
                Incident.organization_id == organization_id,
                Incident.assigned_user_id == user_id,
                Incident.status != IncidentStatus.RESOLVED,
            )
            .with_for_update()
        )
    )
    for incident in incidents:
        incident.assigned_user_id = None
        incident.version += 1
        await emit(
            db,
            incident,
            EventType.UNASSIGNED,
            at=now,
            details={"previous_assignee_user_id": str(user_id), "reason": MEMBERSHIP_INACTIVE},
        )
        record(
            db,
            AuditAction.INCIDENT_UNASSIGNED_INACTIVE,
            scope="ORGANIZATION",
            organization_id=organization_id,
            actor_kind="SYSTEM",
            entity_kind="incident",
            entity_id=incident.id,
            details={"reason": MEMBERSHIP_INACTIVE},
        )
    return len(incidents)
