"""SYSTEM_ADMIN use cases (FR-PLT-001, -002, -005, -007, -008).

The bootstrap and admin-set changes serialize on one transaction-scoped advisory lock, so
concurrent bootstrap attempts cannot create two first admins and the last-admin invariant
cannot be broken by concurrent deactivations.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from sentinelops import clock
from sentinelops.audit.models import AuditEvent
from sentinelops.audit.service import AuditAction, record
from sentinelops.config import Settings
from sentinelops.errors import AppError
from sentinelops.identity.emails import is_valid_email, normalize_email
from sentinelops.identity.models import AppUser, TokenPurpose, UserStatus
from sentinelops.identity.passwords import PasswordService, validate_new_password
from sentinelops.identity.service import ACTIVATION_TOKEN_TTL, InvalidTokenError, issue_token
from sentinelops.identity.sessions import revoke_user_sessions
from sentinelops.identity.tokens import hash_token, new_token
from sentinelops.platform.models import (
    PlatformAdmin,
    PlatformAdminInvitation,
    PlatformAdminStatus,
    PlatformSettings,
)

# Arbitrary constant identifying the platform-admin advisory lock ("SNTL").
PLATFORM_ADMIN_LOCK_KEY = 0x534E544C
# Not fixed by the baseline; short because the invitation grants SYSTEM_ADMIN.
ADMIN_INVITATION_TTL = timedelta(hours=24)


class BootstrapRefusedError(Exception):
    """Raised by the CLI-only bootstrap/recovery paths; message is safe to print."""


async def _lock_platform_admins(db: AsyncSession) -> None:
    await db.execute(select(func.pg_advisory_xact_lock(PLATFORM_ADMIN_LOCK_KEY)))


async def _active_admin_count(db: AsyncSession, *, excluding: uuid.UUID | None = None) -> int:
    stmt = (
        select(func.count())
        .select_from(PlatformAdmin)
        .join(AppUser, AppUser.id == PlatformAdmin.user_id)
        .where(PlatformAdmin.status == PlatformAdminStatus.ACTIVE)
        .where(AppUser.status == UserStatus.ACTIVE)
    )
    if excluding is not None:
        stmt = stmt.where(PlatformAdmin.user_id != excluding)
    return int(await db.scalar(stmt) or 0)


async def is_active_platform_admin(db: AsyncSession, user_id: uuid.UUID) -> bool:
    status = await db.scalar(select(PlatformAdmin.status).where(PlatformAdmin.user_id == user_id))
    return status == PlatformAdminStatus.ACTIVE


def _activation_url(settings: Settings, token: str) -> str:
    # Token in the URL fragment: never sent to servers or written to access logs.
    return f"{settings.public_base_url}/activate#token={token}"


async def bootstrap_system_admin(db: AsyncSession, settings: Settings, *, email: str) -> str:
    """Create the first SYSTEM_ADMIN with no password; return the one-time activation URL."""
    if not is_valid_email(email):
        raise BootstrapRefusedError("Invalid email address.")
    await _lock_platform_admins(db)
    exists = await db.scalar(
        select(PlatformAdmin.user_id).where(PlatformAdmin.status == PlatformAdminStatus.ACTIVE)
    )
    if exists is not None:
        raise BootstrapRefusedError(
            "A SYSTEM_ADMIN already exists. Bootstrap runs only once;"
            " use --recover to regain access."
        )
    email_normalized = normalize_email(email)
    if await db.scalar(select(AppUser.id).where(AppUser.email_normalized == email_normalized)):
        raise BootstrapRefusedError("An account with this email already exists.")

    now = clock.now()
    user = AppUser(
        email=email.strip(),
        email_normalized=email_normalized,
        password_hash=None,
        status=UserStatus.PENDING_ACTIVATION,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    await db.flush()
    db.add(PlatformAdmin(user_id=user.id, status=PlatformAdminStatus.ACTIVE, granted_at=now))
    token = await issue_token(
        db, user_id=user.id, purpose=TokenPurpose.ACTIVATION, ttl=ACTIVATION_TOKEN_TTL
    )
    record(
        db,
        AuditAction.BOOTSTRAP,
        actor_kind="CLI",
        actor_plane="PLATFORM",
        entity_kind="user",
        entity_id=user.id,
    )
    await db.commit()
    return _activation_url(settings, token)


async def recover_system_admin(db: AsyncSession, settings: Settings, *, email: str) -> str:
    """Reset an ACTIVE SYSTEM_ADMIN to pending activation and return a new activation URL."""
    await _lock_platform_admins(db)
    user = await db.scalar(
        select(AppUser)
        .join(PlatformAdmin, PlatformAdmin.user_id == AppUser.id)
        .where(AppUser.email_normalized == normalize_email(email))
        .where(PlatformAdmin.status == PlatformAdminStatus.ACTIVE)
        .with_for_update(of=AppUser)
    )
    if user is None:
        raise BootstrapRefusedError("No active SYSTEM_ADMIN has this email address.")
    now = clock.now()
    user.password_hash = None
    user.status = UserStatus.PENDING_ACTIVATION
    user.version += 1
    revoked = await revoke_user_sessions(db, user.id, now)
    token = await issue_token(
        db, user_id=user.id, purpose=TokenPurpose.ACTIVATION, ttl=ACTIVATION_TOKEN_TTL
    )
    record(
        db,
        AuditAction.RECOVERY,
        actor_kind="CLI",
        actor_plane="PLATFORM",
        entity_kind="user",
        entity_id=user.id,
        details={"sessions_revoked": revoked},
    )
    await db.commit()
    return _activation_url(settings, token)


@dataclass(frozen=True)
class AdminRow:
    user_id: uuid.UUID
    email: str
    user_status: str
    status: str
    granted_at: datetime
    granted_by_email: str | None
    deactivated_at: datetime | None


@dataclass(frozen=True)
class InvitationRow:
    id: uuid.UUID
    email: str
    invited_by_email: str
    created_at: datetime
    expires_at: datetime


async def list_admins(db: AsyncSession) -> tuple[list[AdminRow], list[InvitationRow]]:
    granter = aliased(AppUser)
    admins = [
        AdminRow(
            user_id=pa.user_id,
            email=user.email,
            user_status=user.status,
            status=pa.status,
            granted_at=pa.granted_at,
            granted_by_email=granter_email,
            deactivated_at=pa.deactivated_at,
        )
        for pa, user, granter_email in (
            await db.execute(
                select(PlatformAdmin, AppUser, granter.email)
                .join(AppUser, AppUser.id == PlatformAdmin.user_id)
                .outerjoin(granter, granter.id == PlatformAdmin.granted_by)
                .order_by(PlatformAdmin.granted_at)
            )
        )
    ]
    now = clock.now()
    invitations = [
        InvitationRow(inv.id, inv.email_normalized, inviter_email, inv.created_at, inv.expires_at)
        for inv, inviter_email in (
            await db.execute(
                select(PlatformAdminInvitation, AppUser.email)
                .join(AppUser, AppUser.id == PlatformAdminInvitation.invited_by)
                .where(
                    PlatformAdminInvitation.accepted_at.is_(None),
                    PlatformAdminInvitation.revoked_at.is_(None),
                    PlatformAdminInvitation.expires_at > now,
                )
                .order_by(PlatformAdminInvitation.created_at.desc())
            )
        )
    ]
    return admins, invitations


async def invite_admin(
    db: AsyncSession, *, actor_id: uuid.UUID, email: str
) -> tuple[PlatformAdminInvitation, str]:
    """Create a single-use SYSTEM_ADMIN invitation. Returns (invitation, raw token for email)."""
    if not is_valid_email(email):
        raise AppError(422, "INVALID_EMAIL", "Enter a valid email address")
    email_normalized = normalize_email(email)
    await _lock_platform_admins(db)
    already = await db.scalar(
        select(PlatformAdmin.user_id)
        .join(AppUser, AppUser.id == PlatformAdmin.user_id)
        .where(AppUser.email_normalized == email_normalized)
        .where(PlatformAdmin.status == PlatformAdminStatus.ACTIVE)
    )
    if already is not None:
        raise AppError(
            409, "ALREADY_PLATFORM_ADMIN", "This account is already a platform administrator"
        )
    now = clock.now()
    await db.execute(
        update(PlatformAdminInvitation)
        .where(
            PlatformAdminInvitation.email_normalized == email_normalized,
            PlatformAdminInvitation.accepted_at.is_(None),
            PlatformAdminInvitation.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    token = new_token()
    invitation = PlatformAdminInvitation(
        email_normalized=email_normalized,
        token_hash=hash_token(token),
        invited_by=actor_id,
        expires_at=now + ADMIN_INVITATION_TTL,
        created_at=now,
    )
    db.add(invitation)
    await db.flush()
    record(
        db,
        AuditAction.ADMIN_INVITED,
        actor_user_id=actor_id,
        actor_plane="PLATFORM",
        entity_kind="platform_admin_invitation",
        entity_id=invitation.id,
    )
    await db.commit()
    return invitation, token


async def revoke_invitation(
    db: AsyncSession, *, actor_id: uuid.UUID, invitation_id: uuid.UUID
) -> None:
    result = await db.execute(
        update(PlatformAdminInvitation)
        .where(
            PlatformAdminInvitation.id == invitation_id,
            PlatformAdminInvitation.accepted_at.is_(None),
            PlatformAdminInvitation.revoked_at.is_(None),
        )
        .values(revoked_at=clock.now())
    )
    if not getattr(result, "rowcount", 0):
        raise AppError(404, "NOT_FOUND", "Invitation not found")
    record(
        db,
        AuditAction.ADMIN_INVITATION_REVOKED,
        actor_user_id=actor_id,
        actor_plane="PLATFORM",
        entity_kind="platform_admin_invitation",
        entity_id=invitation_id,
    )
    await db.commit()


async def accept_invitation(
    db: AsyncSession,
    passwords: PasswordService,
    *,
    token: str,
    signed_in_user_id: uuid.UUID | None,
    password: str | None,
) -> None:
    """Grant SYSTEM_ADMIN from a valid invitation.

    A new email creates an ACTIVE account with the supplied password. An existing account must be
    signed in as itself. All of the user's sessions are revoked (rotation on privilege change).
    """
    await _lock_platform_admins(db)
    invitation = await db.scalar(
        select(PlatformAdminInvitation)
        .where(PlatformAdminInvitation.token_hash == hash_token(token))
        .with_for_update()
    )
    now = clock.now()
    if (
        invitation is None
        or invitation.accepted_at is not None
        or invitation.revoked_at is not None
        or invitation.expires_at <= now
    ):
        raise InvalidTokenError

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

    admin = await db.get(PlatformAdmin, user.id, with_for_update=True)
    if admin is None:
        db.add(
            PlatformAdmin(
                user_id=user.id,
                status=PlatformAdminStatus.ACTIVE,
                granted_by=invitation.invited_by,
                granted_at=now,
            )
        )
    else:
        admin.status = PlatformAdminStatus.ACTIVE
        admin.granted_by = invitation.invited_by
        admin.granted_at = now
        admin.deactivated_at = None
        admin.deactivated_by = None
        admin.version += 1
    invitation.accepted_at = now
    invitation.accepted_user_id = user.id
    revoked = await revoke_user_sessions(db, user.id, now)
    record(
        db,
        AuditAction.ADMIN_INVITATION_ACCEPTED,
        actor_user_id=user.id,
        actor_plane="PLATFORM",
        entity_kind="platform_admin_invitation",
        entity_id=invitation.id,
        details={"granted_by": str(invitation.invited_by), "sessions_revoked": revoked},
    )
    await db.commit()


async def deactivate_admin(
    db: AsyncSession, *, actor_id: uuid.UUID, target_user_id: uuid.UUID
) -> None:
    if target_user_id == actor_id:
        raise AppError(403, "CANNOT_DEACTIVATE_SELF", "You cannot deactivate your own account")
    await _lock_platform_admins(db)
    admin = await db.get(PlatformAdmin, target_user_id, with_for_update=True)
    if admin is None or admin.status != PlatformAdminStatus.ACTIVE:
        raise AppError(404, "NOT_FOUND", "Active platform administrator not found")
    if await _active_admin_count(db, excluding=target_user_id) < 1:
        raise AppError(
            409,
            "LAST_PLATFORM_ADMIN",
            "The last active platform administrator cannot be deactivated",
        )
    now = clock.now()
    admin.status = PlatformAdminStatus.DEACTIVATED
    admin.deactivated_at = now
    admin.deactivated_by = actor_id
    admin.version += 1
    revoked = await revoke_user_sessions(db, target_user_id, now)
    record(
        db,
        AuditAction.ADMIN_DEACTIVATED,
        actor_user_id=actor_id,
        actor_plane="PLATFORM",
        entity_kind="user",
        entity_id=target_user_id,
        details={"sessions_revoked": revoked},
    )
    await db.commit()


SETTINGS_FIELDS = (
    "default_max_monitors",
    "min_interval_seconds",
    "max_timeout_ms",
    "max_retry_attempts",
    "max_custom_headers",
    "validation_max_bytes",
    "check_now_per_monitor_seconds",
    "check_now_per_org_hour",
    "default_max_status_pages",
    "default_max_channels",
)


async def get_settings_row(db: AsyncSession) -> PlatformSettings:
    row = await db.get(PlatformSettings, 1)
    if row is None:  # created by migration 0001
        raise AppError(500, "SETTINGS_MISSING", "Platform settings are not initialized")
    return row


async def update_settings(
    db: AsyncSession, *, actor_id: uuid.UUID, version: int, values: dict[str, int]
) -> PlatformSettings:
    row = await db.get(PlatformSettings, 1, with_for_update=True)
    if row is None:
        raise AppError(500, "SETTINGS_MISSING", "Platform settings are not initialized")
    if row.version != version:
        raise AppError(409, "VERSION_CONFLICT", "Settings were changed by someone else; reload")
    changes: dict[str, Any] = {}
    for field in SETTINGS_FIELDS:
        new = values[field]
        old = getattr(row, field)
        if new != old:
            changes[field] = {"from": old, "to": new}
            setattr(row, field, new)
    row.updated_by = actor_id
    row.version += 1
    record(
        db,
        AuditAction.SETTINGS_UPDATED,
        actor_user_id=actor_id,
        actor_plane="PLATFORM",
        entity_kind="platform_settings",
        details={"changes": changes},
    )
    await db.commit()
    return row


@dataclass(frozen=True)
class AuditRow:
    id: uuid.UUID
    at: datetime
    action: str
    actor_kind: str
    actor_email: str | None
    entity_kind: str | None
    entity_id: uuid.UUID | None
    details: dict[str, Any]
    request_id: str | None


async def list_audit(
    db: AsyncSession, *, limit: int, before: datetime | None = None
) -> list[AuditRow]:
    stmt = (
        select(AuditEvent, AppUser.email)
        .outerjoin(AppUser, AppUser.id == AuditEvent.actor_user_id)
        .where(AuditEvent.scope == "PLATFORM")
        .order_by(AuditEvent.at.desc(), AuditEvent.id.desc())
        .limit(limit)
    )
    if before is not None:
        stmt = stmt.where(AuditEvent.at < before)
    return [
        AuditRow(
            ev.id,
            ev.at,
            ev.action,
            ev.actor_kind,
            actor_email,
            ev.entity_kind,
            ev.entity_id,
            ev.safe_diff_json,
            ev.request_id,
        )
        for ev, actor_email in await db.execute(stmt)
    ]


@dataclass(frozen=True)
class DashboardData:
    active_admins: int
    pending_invitations: int
    recent_audit: list[AuditRow]


async def dashboard(db: AsyncSession) -> DashboardData:
    _admins, invitations = await list_admins(db)
    return DashboardData(
        active_admins=await _active_admin_count(db),
        pending_invitations=len(invitations),
        recent_audit=await list_audit(db, limit=10),
    )
