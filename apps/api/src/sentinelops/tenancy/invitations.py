"""Organization invitations (FR-ID-002): single-use, hashed, email-bound, 7-day expiry."""

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.errors import AppError
from sentinelops.identity.emails import is_valid_email, normalize_email
from sentinelops.identity.models import AppUser, UserStatus
from sentinelops.identity.passwords import PasswordService, validate_new_password
from sentinelops.identity.service import InvalidTokenError
from sentinelops.identity.tokens import hash_token, new_token
from sentinelops.tenancy.locks import lock_organization
from sentinelops.tenancy.models import (
    MemberStatus,
    Organization,
    OrganizationMember,
    OrgInvitation,
    OrgRole,
    OrgStatus,
)

ORG_INVITATION_TTL = timedelta(days=7)


async def create_invitation(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    email: str,
    role: str,
    invited_by: uuid.UUID,
    plane: str,
) -> tuple[OrgInvitation, str]:
    """Create an invitation (revoking any pending one for the same email). Caller holds the
    organization lock and has checked the inviter may grant ``role``. Does not commit."""
    if not is_valid_email(email):
        raise AppError(422, "INVALID_EMAIL", "Enter a valid email address")
    if role not in OrgRole.ALL:
        raise AppError(422, "INVALID_ROLE", "Unknown organization role")
    email_normalized = normalize_email(email)
    existing = await db.scalar(
        select(OrganizationMember.status)
        .join(AppUser, AppUser.id == OrganizationMember.user_id)
        .where(
            OrganizationMember.organization_id == organization_id,
            AppUser.email_normalized == email_normalized,
        )
    )
    if existing in (MemberStatus.ACTIVE, MemberStatus.SUSPENDED):
        raise AppError(409, "ALREADY_MEMBER", "This person already has a membership here")
    now = clock.now()
    await db.execute(
        update(OrgInvitation)
        .where(
            OrgInvitation.organization_id == organization_id,
            OrgInvitation.email_normalized == email_normalized,
            OrgInvitation.accepted_at.is_(None),
            OrgInvitation.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    token = new_token()
    invitation = OrgInvitation(
        organization_id=organization_id,
        email_normalized=email_normalized,
        role=role,
        token_hash=hash_token(token),
        invited_by=invited_by,
        invited_by_plane=plane,
        expires_at=now + ORG_INVITATION_TTL,
        created_at=now,
    )
    db.add(invitation)
    await db.flush()
    return invitation, token


async def _valid_invitation(db: AsyncSession, token: str) -> OrgInvitation:
    invitation = await db.scalar(
        select(OrgInvitation).where(OrgInvitation.token_hash == hash_token(token)).with_for_update()
    )
    if (
        invitation is None
        or invitation.accepted_at is not None
        or invitation.revoked_at is not None
        or invitation.expires_at <= clock.now()
    ):
        raise InvalidTokenError
    return invitation


@dataclass(frozen=True)
class InvitationPreview:
    organization_name: str
    role: str
    email: str
    account_exists: bool


async def preview_invitation(db: AsyncSession, token: str) -> InvitationPreview:
    invitation = await _valid_invitation(db, token)
    organization = await db.get(Organization, invitation.organization_id)
    exists = await db.scalar(
        select(AppUser.id).where(AppUser.email_normalized == invitation.email_normalized)
    )
    preview = InvitationPreview(
        organization_name=organization.name if organization else "",
        role=invitation.role,
        email=invitation.email_normalized,
        account_exists=exists is not None,
    )
    await db.rollback()  # release the row lock; preview never changes state
    return preview


async def accept_invitation(
    db: AsyncSession,
    passwords: PasswordService,
    *,
    token: str,
    signed_in_user_id: uuid.UUID | None,
    password: str | None,
) -> uuid.UUID:
    """Accept an invitation and return the organization ID.

    New email: creates an ACTIVE account with the supplied password. Existing account: must be
    signed in as itself. A REMOVED membership is restored with the invited role.
    """
    invitation = await _valid_invitation(db, token)
    organization = await lock_organization(db, invitation.organization_id)
    if organization is None:
        raise InvalidTokenError
    if organization.status == OrgStatus.SUSPENDED:
        raise AppError(403, "ORG_SUSPENDED", "This organization is suspended")
    now = clock.now()
    user = await db.scalar(
        select(AppUser).where(AppUser.email_normalized == invitation.email_normalized)
    )
    if user is None:
        if password is None:
            raise AppError(422, "PASSWORD_REQUIRED", "Choose a password to create your account")
        validate_new_password(password, invitation.email_normalized)
        user = AppUser(
            email=invitation.email_normalized,
            email_normalized=invitation.email_normalized,
            password_hash=passwords.hash(password),
            status=UserStatus.ACTIVE,
            email_verified_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(user)
        await db.flush()
    elif signed_in_user_id != user.id:
        raise AppError(
            401, "SIGN_IN_REQUIRED", "Sign in with the invited account to accept this invitation"
        )
    elif user.status != UserStatus.ACTIVE:
        raise InvalidTokenError

    member = await db.get(OrganizationMember, (organization.id, user.id), with_for_update=True)
    if member is not None and member.status != MemberStatus.REMOVED:
        raise AppError(409, "ALREADY_MEMBER", "You already have a membership in this organization")
    if member is None:
        db.add(
            OrganizationMember(
                organization_id=organization.id,
                user_id=user.id,
                role=invitation.role,
                status=MemberStatus.ACTIVE,
                invited_by=invitation.invited_by,
                joined_at=now,
                status_changed_at=now,
            )
        )
    else:
        member.role = invitation.role
        member.status = MemberStatus.ACTIVE
        member.invited_by = invitation.invited_by
        member.joined_at = now
        member.status_changed_at = now
        member.version += 1
    invitation.accepted_at = now
    invitation.accepted_user_id = user.id
    record(
        db,
        AuditAction.MEMBER_JOINED,
        scope="ORGANIZATION",
        organization_id=organization.id,
        actor_user_id=user.id,
        actor_plane="ORG",
        entity_kind="org_invitation",
        entity_id=invitation.id,
        details={"role": invitation.role},
    )
    await db.commit()
    return organization.id
