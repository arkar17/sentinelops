"""SYSTEM_ADMIN organization lifecycle (FR-PLT-003/004/006/008).

Returns metadata only (FR-PLT-006 allowlist): never member lists beyond owner contacts, project
names, monitor data or anything decrypted. The SYSTEM_ADMIN never becomes a member here.
"""

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.catalog.eligibility import (
    bump_organization_generations,
    reset_organization_health,
)
from sentinelops.catalog.models import Project
from sentinelops.errors import AppError
from sentinelops.identity.models import AppUser
from sentinelops.notifications.outbox import ORG_SUSPENDED_REASON, cancel_pending
from sentinelops.tenancy.invitations import create_invitation
from sentinelops.tenancy.limits import LIMIT_FIELDS, EffectiveLimits, effective_limits
from sentinelops.tenancy.locks import active_owner_count, lock_organization
from sentinelops.tenancy.models import (
    MemberStatus,
    Organization,
    OrganizationLimit,
    OrganizationMember,
    OrgInvitation,
    OrgRole,
    OrgStatus,
)
from sentinelops.tenancy.service import validate_timezone

SLUG_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,46}[a-z0-9])$")


class OrgNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__(404, "NOT_FOUND", "Organization not found")


def _validate_slug(slug: str) -> str:
    if not SLUG_PATTERN.fullmatch(slug):
        raise AppError(
            422, "INVALID_SLUG", "Slug: 3-48 lowercase letters, digits or hyphens, no edge hyphen"
        )
    return slug


def _audit(
    db: AsyncSession, actor_id: uuid.UUID, action: str, org_id: uuid.UUID, **details: Any
) -> None:
    record(
        db,
        action,
        scope="PLATFORM",
        organization_id=org_id,
        actor_user_id=actor_id,
        actor_plane="PLATFORM",
        entity_kind="organization",
        entity_id=org_id,
        details=details or None,
    )


@dataclass(frozen=True)
class OrgMetadata:
    id: uuid.UUID
    slug: str
    name: str
    timezone: str
    status: str
    suspended_at: datetime | None
    suspended_reason: str | None
    created_at: datetime
    version: int
    owner_emails: list[str]
    member_count: int
    project_count: int
    pending_owner_invitation: bool
    limit_overrides: dict[str, int | None]
    effective_limits: EffectiveLimits


async def _metadata(db: AsyncSession, organization: Organization) -> OrgMetadata:
    org_id = organization.id
    owners = list(
        await db.scalars(
            select(AppUser.email)
            .join(OrganizationMember, OrganizationMember.user_id == AppUser.id)
            .where(
                OrganizationMember.organization_id == org_id,
                OrganizationMember.role == OrgRole.OWNER,
                OrganizationMember.status == MemberStatus.ACTIVE,
            )
            .order_by(AppUser.email_normalized)
        )
    )
    members = await db.scalar(
        select(func.count())
        .select_from(OrganizationMember)
        .where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.status == MemberStatus.ACTIVE,
        )
    )
    projects = await db.scalar(
        select(func.count())
        .select_from(Project)
        .where(Project.organization_id == org_id, Project.archived_at.is_(None))
    )
    pending_owner = await db.scalar(
        select(OrgInvitation.id)
        .where(
            OrgInvitation.organization_id == org_id,
            OrgInvitation.role == OrgRole.OWNER,
            OrgInvitation.accepted_at.is_(None),
            OrgInvitation.revoked_at.is_(None),
            OrgInvitation.expires_at > clock.now(),
        )
        .limit(1)
    )
    override = await db.get(OrganizationLimit, org_id)
    return OrgMetadata(
        id=org_id,
        slug=organization.slug,
        name=organization.name,
        timezone=organization.timezone,
        status=organization.status,
        suspended_at=organization.suspended_at,
        suspended_reason=organization.suspended_reason,
        created_at=organization.created_at,
        version=organization.version,
        owner_emails=owners,
        member_count=int(members or 0),
        project_count=int(projects or 0),
        pending_owner_invitation=pending_owner is not None,
        limit_overrides={f: getattr(override, f) if override else None for f in LIMIT_FIELDS},
        effective_limits=await effective_limits(db, org_id),
    )


async def list_organizations(db: AsyncSession) -> list[OrgMetadata]:
    orgs = await db.scalars(select(Organization).order_by(Organization.name))
    return [await _metadata(db, o) for o in orgs]


async def get_organization(db: AsyncSession, org_id: uuid.UUID) -> OrgMetadata:
    organization = await db.get(Organization, org_id)
    if organization is None:
        raise OrgNotFoundError
    return await _metadata(db, organization)


async def org_counts_by_status(db: AsyncSession) -> dict[str, int]:
    rows = await db.execute(select(Organization.status, func.count()).group_by(Organization.status))
    counts = {OrgStatus.ACTIVE: 0, OrgStatus.SUSPENDED: 0}
    for status, count in rows:
        counts[status] = int(count)
    return counts


async def create_organization(
    db: AsyncSession,
    *,
    actor_id: uuid.UUID,
    name: str,
    slug: str,
    timezone: str,
    owner_email: str,
) -> tuple[OrgMetadata, OrgInvitation, str]:
    """Create an ACTIVE organization with an ORG_OWNER invitation. The creator is not a member."""
    now = clock.now()
    organization = Organization(
        slug=_validate_slug(slug),
        name=name,
        timezone=validate_timezone(timezone),
        status=OrgStatus.ACTIVE,
        created_by=actor_id,
        created_at=now,
        updated_at=now,
    )
    db.add(organization)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise AppError(409, "SLUG_TAKEN", "This slug is already in use") from exc
    invitation, token = await create_invitation(
        db,
        organization_id=organization.id,
        email=owner_email,
        role=OrgRole.OWNER,
        invited_by=actor_id,
        plane="PLATFORM",
    )
    _audit(db, actor_id, AuditAction.ORG_CREATED, organization.id, slug=slug)
    _audit(db, actor_id, AuditAction.ORG_OWNER_INVITED, organization.id)
    await db.commit()
    return await _metadata(db, organization), invitation, token


async def _locked(db: AsyncSession, org_id: uuid.UUID) -> Organization:
    organization = await lock_organization(db, org_id)
    if organization is None:
        raise OrgNotFoundError
    return organization


async def update_organization(
    db: AsyncSession,
    *,
    actor_id: uuid.UUID,
    org_id: uuid.UUID,
    version: int,
    name: str | None,
    slug: str | None,
    timezone: str | None,
) -> OrgMetadata:
    organization = await _locked(db, org_id)
    if organization.version != version:
        raise AppError(409, "VERSION_CONFLICT", "The organization was changed; reload")
    changes: dict[str, Any] = {}
    for field, value, validate in (
        ("name", name, None),
        ("slug", slug, _validate_slug),
        ("timezone", timezone, validate_timezone),
    ):
        if value is not None and value != getattr(organization, field):
            changes[field] = {"from": getattr(organization, field), "to": value}
            setattr(organization, field, validate(value) if validate else value)
    organization.version += 1
    _audit(db, actor_id, AuditAction.ORG_UPDATED, org_id, changes=changes)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise AppError(409, "SLUG_TAKEN", "This slug is already in use") from exc
    return await _metadata(db, organization)


async def suspend_organization(
    db: AsyncSession, *, actor_id: uuid.UUID, org_id: uuid.UUID, reason: str
) -> OrgMetadata:
    organization = await _locked(db, org_id)
    if organization.status != OrgStatus.SUSPENDED:
        organization.status = OrgStatus.SUSPENDED
        organization.suspended_at = clock.now()
        organization.suspended_reason = reason
        organization.version += 1
        # Claims stop via the ACTIVE join; in-flight jobs are invalidated (FR-PLT-004).
        # G5 adds cancellation of pending notifications here.
        await bump_organization_generations(db, org_id)
        cancelled = await cancel_pending(db, org_id, ORG_SUSPENDED_REASON)
        _audit(
            db,
            actor_id,
            AuditAction.ORG_SUSPENDED,
            org_id,
            reason=reason,
            cancelled_notifications=cancelled,
        )
        await db.commit()
    return await _metadata(db, organization)


async def activate_organization(
    db: AsyncSession, *, actor_id: uuid.UUID, org_id: uuid.UUID
) -> OrgMetadata:
    organization = await _locked(db, org_id)
    if organization.status != OrgStatus.ACTIVE:
        organization.status = OrgStatus.ACTIVE
        organization.suspended_at = None
        organization.suspended_reason = None
        organization.version += 1
        await bump_organization_generations(db, org_id)
        await reset_organization_health(db, org_id)
        _audit(db, actor_id, AuditAction.ORG_ACTIVATED, org_id)
        await db.commit()
    return await _metadata(db, organization)


async def set_limits(
    db: AsyncSession, *, actor_id: uuid.UUID, org_id: uuid.UUID, values: dict[str, int | None]
) -> OrgMetadata:
    organization = await _locked(db, org_id)
    override = await db.get(OrganizationLimit, org_id, with_for_update=True)
    if override is None:
        override = OrganizationLimit(organization_id=org_id, updated_at=clock.now())
        db.add(override)
    changes = {
        field: {"from": getattr(override, field), "to": values[field]}
        for field in LIMIT_FIELDS
        if getattr(override, field) != values[field]
    }
    for field in LIMIT_FIELDS:
        setattr(override, field, values[field])
    override.updated_by = actor_id
    override.version = (override.version or 0) + 1
    _audit(db, actor_id, AuditAction.ORG_LIMITS_UPDATED, org_id, changes=changes)
    await db.commit()
    return await _metadata(db, organization)


async def invite_owner(
    db: AsyncSession, *, actor_id: uuid.UUID, org_id: uuid.UUID, email: str
) -> tuple[OrgInvitation, str, str]:
    """PLT.org.owner_invite: only while the organization has no ACTIVE ORG_OWNER, so a
    SYSTEM_ADMIN cannot grant itself access to an owned organization."""
    organization = await _locked(db, org_id)
    if await active_owner_count(db, org_id) > 0:
        raise AppError(
            409,
            "ORGANIZATION_HAS_OWNER",
            "Owner invitations can only be issued while the organization has no active owner",
        )
    invitation, token = await create_invitation(
        db,
        organization_id=org_id,
        email=email,
        role=OrgRole.OWNER,
        invited_by=actor_id,
        plane="PLATFORM",
    )
    _audit(db, actor_id, AuditAction.ORG_OWNER_INVITED, org_id)
    await db.commit()
    return invitation, token, organization.name
