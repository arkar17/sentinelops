"""Organization row lock: serializes membership, limit and lifecycle changes per organization."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.tenancy.models import MemberStatus, Organization, OrganizationMember, OrgRole


async def lock_organization(db: AsyncSession, organization_id: uuid.UUID) -> Organization | None:
    return await db.scalar(
        select(Organization).where(Organization.id == organization_id).with_for_update()
    )


async def active_owner_count(
    db: AsyncSession, organization_id: uuid.UUID, *, excluding: uuid.UUID | None = None
) -> int:
    stmt = (
        select(func.count())
        .select_from(OrganizationMember)
        .where(
            OrganizationMember.organization_id == organization_id,
            OrganizationMember.role == OrgRole.OWNER,
            OrganizationMember.status == MemberStatus.ACTIVE,
        )
    )
    if excluding is not None:
        stmt = stmt.where(OrganizationMember.user_id != excluding)
    return int(await db.scalar(stmt) or 0)
