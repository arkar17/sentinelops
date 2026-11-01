"""Email recipients leave every channel when their membership becomes inactive
(PERMISSION_MATRIX.md §4 rule 5). Secret-free: tenancy (used by the platform plane) calls it."""

import uuid

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.notifications.models import NotificationChannelRecipient


async def remove_member_recipients(
    db: AsyncSession, organization_id: uuid.UUID, user_id: uuid.UUID
) -> int:
    """No commit; runs inside the membership change's transaction."""
    result = await db.execute(
        delete(NotificationChannelRecipient)
        .where(
            NotificationChannelRecipient.organization_id == organization_id,
            NotificationChannelRecipient.user_id == user_id,
        )
        .execution_options(synchronize_session=False)
    )
    return int(getattr(result, "rowcount", 0) or 0)
