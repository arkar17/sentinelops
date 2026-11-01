"""Organization-plane use cases. Every query is scoped by the context's organization_id.

Membership mutations lock the organization row first, then re-read the actor's membership, so
permission and last-owner checks use state that cannot change until commit (FR-ORG-002).
"""

import uuid
import zoneinfo
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.models import AuditEvent
from sentinelops.audit.service import AuditAction, record
from sentinelops.catalog.models import Project
from sentinelops.errors import AppError
from sentinelops.identity.models import AppUser
from sentinelops.incidents.assignments import unassign_member
from sentinelops.notifications.recipients import remove_member_recipients
from sentinelops.tenancy.context import OrgContext, OrgNotFoundError, check_access, load_membership
from sentinelops.tenancy.invitations import create_invitation
from sentinelops.tenancy.limits import EffectiveLimits, effective_limits
from sentinelops.tenancy.locks import active_owner_count, lock_organization
from sentinelops.tenancy.models import (
    MemberStatus,
    Organization,
    OrganizationMember,
    OrgInvitation,
    OrgRole,
    UserPreference,
)
from sentinelops.tenancy.rules import can_invite, can_manage


class LastOwnerError(AppError):
    def __init__(self) -> None:
        super().__init__(409, "LAST_OWNER", "The organization must keep at least one active owner")


def validate_timezone(value: str) -> str:
    if value not in zoneinfo.available_timezones() and value != "UTC":
        raise AppError(422, "INVALID_TIMEZONE", "Use an IANA time zone such as Europe/Berlin")
    return value


def _audit(db: AsyncSession, ctx: OrgContext, action: str, **kwargs: Any) -> None:
    record(
        db,
        action,
        scope="ORGANIZATION",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        actor_plane="ORG",
        **kwargs,
    )


async def _lock_and_recheck(db: AsyncSession, ctx: OrgContext, action: str) -> str:
    """Lock the organization and re-validate the actor; returns the actor's current role."""
    if await lock_organization(db, ctx.organization_id) is None:
        raise OrgNotFoundError
    found = await load_membership(db, ctx.organization_id, ctx.user_id)
    if found is None:
        raise OrgNotFoundError
    organization, member = found
    check_access(organization, member.role, action)
    return member.role


async def _target_member(
    db: AsyncSession, ctx: OrgContext, user_id: uuid.UUID
) -> OrganizationMember:
    member = await db.get(OrganizationMember, (ctx.organization_id, user_id), with_for_update=True)
    if member is None or member.status == MemberStatus.REMOVED:
        raise AppError(404, "NOT_FOUND", "Member not found")
    return member


# --- profile -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class OrgProfile:
    id: uuid.UUID
    slug: str
    name: str
    timezone: str
    status: str
    version: int
    my_role: str
    limits: EffectiveLimits
    member_count: int
    project_count: int


async def get_profile(db: AsyncSession, ctx: OrgContext) -> OrgProfile:
    organization = await db.get(Organization, ctx.organization_id)
    if organization is None:
        raise OrgNotFoundError
    members = await db.scalar(
        select(func.count())
        .select_from(OrganizationMember)
        .where(
            OrganizationMember.organization_id == ctx.organization_id,
            OrganizationMember.status == MemberStatus.ACTIVE,
        )
    )
    projects = await db.scalar(
        select(func.count())
        .select_from(Project)
        .where(Project.organization_id == ctx.organization_id, Project.archived_at.is_(None))
    )
    return OrgProfile(
        id=organization.id,
        slug=organization.slug,
        name=organization.name,
        timezone=organization.timezone,
        status=organization.status,
        version=organization.version,
        my_role=ctx.role,
        limits=await effective_limits(db, ctx.organization_id),
        member_count=int(members or 0),
        project_count=int(projects or 0),
    )


async def update_profile(
    db: AsyncSession, ctx: OrgContext, *, version: int, name: str | None, timezone: str | None
) -> OrgProfile:
    await _lock_and_recheck(db, ctx, "ORG.update")
    organization = await db.get(Organization, ctx.organization_id)
    if organization is None:
        raise OrgNotFoundError
    if organization.version != version:
        raise AppError(409, "VERSION_CONFLICT", "The organization was changed; reload")
    changes: dict[str, Any] = {}
    if name is not None and name != organization.name:
        changes["name"] = {"from": organization.name, "to": name}
        organization.name = name
    if timezone is not None and timezone != organization.timezone:
        changes["timezone"] = {"from": organization.timezone, "to": validate_timezone(timezone)}
        organization.timezone = timezone
    organization.version += 1
    _audit(db, ctx, AuditAction.ORG_PROFILE_UPDATED, details={"changes": changes})
    await db.commit()
    return await get_profile(db, ctx)


# --- members -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class MemberRow:
    user_id: uuid.UUID
    email: str
    role: str
    status: str
    joined_at: datetime


async def list_members(db: AsyncSession, ctx: OrgContext) -> list[MemberRow]:
    rows = await db.execute(
        select(OrganizationMember, AppUser.email)
        .join(AppUser, AppUser.id == OrganizationMember.user_id)
        .where(
            OrganizationMember.organization_id == ctx.organization_id,
            OrganizationMember.status != MemberStatus.REMOVED,
        )
        .order_by(AppUser.email_normalized)
    )
    return [MemberRow(m.user_id, email, m.role, m.status, m.joined_at) for m, email in rows]


@dataclass(frozen=True)
class InvitationRow:
    id: uuid.UUID
    email: str
    role: str
    invited_by_email: str
    created_at: datetime
    expires_at: datetime


async def list_invitations(db: AsyncSession, ctx: OrgContext) -> list[InvitationRow]:
    rows = await db.execute(
        select(OrgInvitation, AppUser.email)
        .join(AppUser, AppUser.id == OrgInvitation.invited_by)
        .where(
            OrgInvitation.organization_id == ctx.organization_id,
            OrgInvitation.accepted_at.is_(None),
            OrgInvitation.revoked_at.is_(None),
            OrgInvitation.expires_at > clock.now(),
        )
        .order_by(OrgInvitation.created_at.desc())
    )
    return [
        InvitationRow(i.id, i.email_normalized, i.role, email, i.created_at, i.expires_at)
        for i, email in rows
    ]


async def invite_member(
    db: AsyncSession, ctx: OrgContext, *, email: str, role: str
) -> tuple[OrgInvitation, str]:
    actor_role = await _lock_and_recheck(db, ctx, "MEM.invite")
    if role not in OrgRole.ALL:
        raise AppError(422, "INVALID_ROLE", "Unknown organization role")
    if not can_invite(actor_role, role):
        raise AppError(403, "FORBIDDEN", "You cannot invite members with this role")
    invitation, token = await create_invitation(
        db,
        organization_id=ctx.organization_id,
        email=email,
        role=role,
        invited_by=ctx.user_id,
        plane="ORG",
    )
    _audit(
        db,
        ctx,
        AuditAction.MEMBER_INVITED,
        entity_kind="org_invitation",
        entity_id=invitation.id,
        details={"role": role},
    )
    await db.commit()
    return invitation, token


async def revoke_invitation(db: AsyncSession, ctx: OrgContext, invitation_id: uuid.UUID) -> None:
    actor_role = await _lock_and_recheck(db, ctx, "MEM.invitation.revoke")
    invitation = await db.scalar(
        select(OrgInvitation).where(
            OrgInvitation.id == invitation_id,
            OrgInvitation.organization_id == ctx.organization_id,
            OrgInvitation.accepted_at.is_(None),
            OrgInvitation.revoked_at.is_(None),
        )
    )
    if invitation is None:
        raise AppError(404, "NOT_FOUND", "Invitation not found")
    if not can_manage(actor_role, invitation.role):
        raise AppError(403, "FORBIDDEN", "You cannot revoke invitations for this role")
    invitation.revoked_at = clock.now()
    _audit(
        db,
        ctx,
        AuditAction.MEMBER_INVITATION_REVOKED,
        entity_kind="org_invitation",
        entity_id=invitation.id,
    )
    await db.commit()


async def change_role(db: AsyncSession, ctx: OrgContext, *, user_id: uuid.UUID, role: str) -> None:
    if role not in OrgRole.ALL:
        raise AppError(422, "INVALID_ROLE", "Unknown organization role")
    actor_role = await _lock_and_recheck(db, ctx, "MEM.role.change")
    target = await _target_member(db, ctx, user_id)
    if target.role == role:
        return
    if user_id == ctx.user_id:
        # Only an owner stepping down, while another active owner exists (rule 3).
        if actor_role != OrgRole.OWNER:
            raise AppError(403, "CANNOT_CHANGE_OWN_ROLE", "You cannot change your own role")
    elif not can_manage(actor_role, target.role, role):
        raise AppError(403, "FORBIDDEN", "You cannot assign this role to this member")
    if (
        target.role == OrgRole.OWNER
        and target.status == MemberStatus.ACTIVE
        and await active_owner_count(db, ctx.organization_id, excluding=user_id) < 1
    ):
        raise LastOwnerError
    previous = target.role
    target.role = role
    target.version += 1
    _audit(
        db,
        ctx,
        AuditAction.MEMBER_ROLE_CHANGED,
        entity_kind="user",
        entity_id=user_id,
        details={"from": previous, "to": role},
    )
    await db.commit()


async def change_status(
    db: AsyncSession, ctx: OrgContext, *, user_id: uuid.UUID, status: str
) -> None:
    if status not in (MemberStatus.ACTIVE, MemberStatus.SUSPENDED):
        raise AppError(422, "INVALID_STATUS", "Status must be ACTIVE or SUSPENDED")
    actor_role = await _lock_and_recheck(db, ctx, "MEM.status.change")
    if user_id == ctx.user_id:
        raise AppError(403, "CANNOT_CHANGE_OWN_STATUS", "You cannot change your own status")
    target = await _target_member(db, ctx, user_id)
    if not can_manage(actor_role, target.role):
        raise AppError(403, "FORBIDDEN", "You cannot change this member's status")
    if target.status == status:
        return
    if (
        status == MemberStatus.SUSPENDED
        and target.role == OrgRole.OWNER
        and await active_owner_count(db, ctx.organization_id, excluding=user_id) < 1
    ):
        raise LastOwnerError
    previous = target.status
    target.status = status
    target.status_changed_at = clock.now()
    target.version += 1
    if status == MemberStatus.SUSPENDED:
        await unassign_member(db, ctx.organization_id, user_id)
        await remove_member_recipients(db, ctx.organization_id, user_id)
    _audit(
        db,
        ctx,
        AuditAction.MEMBER_STATUS_CHANGED,
        entity_kind="user",
        entity_id=user_id,
        details={"from": previous, "to": status},
    )
    await db.commit()


async def remove_member(db: AsyncSession, ctx: OrgContext, *, user_id: uuid.UUID) -> None:
    actor_role = await _lock_and_recheck(db, ctx, "MEM.remove")
    if user_id == ctx.user_id:
        raise AppError(403, "USE_LEAVE", "Use leave to remove yourself")
    target = await _target_member(db, ctx, user_id)
    if not can_manage(actor_role, target.role):
        raise AppError(403, "FORBIDDEN", "You cannot remove this member")
    if (
        target.role == OrgRole.OWNER
        and target.status == MemberStatus.ACTIVE
        and await active_owner_count(db, ctx.organization_id, excluding=user_id) < 1
    ):
        raise LastOwnerError
    target.status = MemberStatus.REMOVED
    target.status_changed_at = clock.now()
    target.version += 1
    await unassign_member(db, ctx.organization_id, user_id)
    await remove_member_recipients(db, ctx.organization_id, user_id)
    _audit(
        db,
        ctx,
        AuditAction.MEMBER_REMOVED,
        entity_kind="user",
        entity_id=user_id,
        details={"role": target.role},
    )
    await db.commit()


async def leave(db: AsyncSession, ctx: OrgContext) -> None:
    actor_role = await _lock_and_recheck(db, ctx, "MEM.leave")
    if (
        actor_role == OrgRole.OWNER
        and await active_owner_count(db, ctx.organization_id, excluding=ctx.user_id) < 1
    ):
        raise LastOwnerError
    member = await _target_member(db, ctx, ctx.user_id)
    member.status = MemberStatus.REMOVED
    member.status_changed_at = clock.now()
    member.version += 1
    await unassign_member(db, ctx.organization_id, ctx.user_id)
    await remove_member_recipients(db, ctx.organization_id, ctx.user_id)
    _audit(db, ctx, AuditAction.MEMBER_LEFT, entity_kind="user", entity_id=ctx.user_id)
    await db.commit()


# --- audit ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class OrgAuditRow:
    id: uuid.UUID
    at: datetime
    scope: str
    action: str
    actor_plane: str
    actor_email: str | None
    entity_kind: str | None
    entity_id: uuid.UUID | None
    details: dict[str, Any]


async def list_audit(
    db: AsyncSession, ctx: OrgContext, *, limit: int, before: datetime | None
) -> list[OrgAuditRow]:
    """Organization-scoped events plus platform actions on this organization (FR-PLT-007)."""
    stmt = (
        select(AuditEvent, AppUser.email)
        .outerjoin(AppUser, AppUser.id == AuditEvent.actor_user_id)
        .where(AuditEvent.organization_id == ctx.organization_id)
        .order_by(AuditEvent.at.desc(), AuditEvent.id.desc())
        .limit(limit)
    )
    if before is not None:
        stmt = stmt.where(AuditEvent.at < before)
    return [
        OrgAuditRow(
            ev.id,
            ev.at,
            ev.scope,
            ev.action,
            ev.actor_plane,
            email,
            ev.entity_kind,
            ev.entity_id,
            ev.safe_diff_json,
        )
        for ev, email in await db.execute(stmt)
    ]


# --- self: memberships and selection (FR-ID-005) --------------------------------------------------


@dataclass(frozen=True)
class MembershipRow:
    organization_id: uuid.UUID
    slug: str
    name: str
    organization_status: str
    role: str


async def my_organizations(
    db: AsyncSession, user_id: uuid.UUID
) -> tuple[list[MembershipRow], uuid.UUID | None]:
    rows = await db.execute(
        select(Organization, OrganizationMember.role)
        .join(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where(
            OrganizationMember.user_id == user_id,
            OrganizationMember.status == MemberStatus.ACTIVE,
        )
        .order_by(Organization.name)
    )
    memberships = [MembershipRow(o.id, o.slug, o.name, o.status, role) for o, role in rows]
    preference = await db.get(UserPreference, user_id)
    selected = preference.selected_org_id if preference else None
    if selected not in {m.organization_id for m in memberships}:
        selected = None  # stale preference (membership ended): never trusted
    return memberships, selected


async def select_organization(
    db: AsyncSession, user_id: uuid.UUID, organization_id: uuid.UUID | None
) -> None:
    if organization_id is not None and await load_membership(db, organization_id, user_id) is None:
        raise OrgNotFoundError
    preference = await db.get(UserPreference, user_id)
    if preference is None:
        db.add(
            UserPreference(user_id=user_id, selected_org_id=organization_id, updated_at=clock.now())
        )
    else:
        preference.selected_org_id = organization_id
    await db.commit()
