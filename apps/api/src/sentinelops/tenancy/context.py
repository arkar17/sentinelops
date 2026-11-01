"""Organization context for every /api/orgs/{org_id} route (02_TECHNICAL_ARCHITECTURE.md §8).

The organization comes only from the URL path and is re-validated against an ACTIVE membership
on every request. platform_admin is never consulted. Non-members (including REMOVED/SUSPENDED
members and SYSTEM_ADMINs without membership) get 404; a SUSPENDED organization gives 403
ORG_SUSPENDED; a member without the permission gets 403.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.authz.matrix import allows
from sentinelops.db.session import DbSession
from sentinelops.errors import AppError
from sentinelops.identity.dependencies import CurrentPrincipal, Principal
from sentinelops.tenancy.models import MemberStatus, Organization, OrganizationMember, OrgStatus


class OrgNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__(404, "NOT_FOUND", "Organization not found")


@dataclass(frozen=True)
class OrgContext:
    organization_id: uuid.UUID
    slug: str
    name: str
    role: str
    principal: Principal

    @property
    def user_id(self) -> uuid.UUID:
        return self.principal.user_id


async def load_membership(
    db: AsyncSession, organization_id: uuid.UUID, user_id: uuid.UUID, *, for_update: bool = False
) -> tuple[Organization, OrganizationMember] | None:
    stmt = (
        select(Organization, OrganizationMember)
        .join(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where(
            Organization.id == organization_id,
            OrganizationMember.user_id == user_id,
            OrganizationMember.status == MemberStatus.ACTIVE,
        )
    )
    if for_update:
        stmt = stmt.with_for_update(of=OrganizationMember)
    row = (await db.execute(stmt)).one_or_none()
    return None if row is None else (row[0], row[1])


def check_access(organization: Organization, role: str, action: str) -> None:
    if organization.status == OrgStatus.SUSPENDED:
        raise AppError(403, "ORG_SUSPENDED", "This organization is suspended")
    if not allows(role, action):
        raise AppError(403, "FORBIDDEN", "You do not have permission to do this")


class OrgPermission:
    """FastAPI dependency declaring the route's PERMISSION_MATRIX action ID."""

    def __init__(self, action: str) -> None:
        self.action = action

    async def __call__(
        self, org_id: uuid.UUID, principal: CurrentPrincipal, db: DbSession
    ) -> OrgContext:
        found = await load_membership(db, org_id, principal.user_id)
        if found is None:
            raise OrgNotFoundError
        organization, member = found
        check_access(organization, member.role, self.action)
        return OrgContext(
            organization.id, organization.slug, organization.name, member.role, principal
        )
