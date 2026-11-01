"""SYSTEM_ADMIN MFA operations: enrolment, login verification, recovery codes, disable and the
operator reset (OD-01). Each runs in one transaction with an audit event; codes, secrets and
recovery codes are never written to the audit log or logs."""

import uuid
from dataclasses import dataclass

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.config import Settings
from sentinelops.errors import AppError
from sentinelops.identity import mfa, throttle
from sentinelops.identity.emails import normalize_email
from sentinelops.identity.models import (
    AdminMfa,
    AdminRecoveryCode,
    AppUser,
    ThrottleScope,
    UserSession,
)
from sentinelops.identity.passwords import PasswordService
from sentinelops.identity.service import InvalidCredentialsError, TooManyAttemptsError
from sentinelops.identity.sessions import (
    IssuedSession,
    create_session,
    revoke_session,
    revoke_user_sessions,
)
from sentinelops.platform.models import PlatformAdmin, PlatformAdminStatus


@dataclass(frozen=True)
class MfaStatus:
    enabled: bool
    required: bool
    pending: str | None
    recovery_codes_left: int


@dataclass(frozen=True)
class Enrollment:
    secret: str
    otpauth_uri: str


async def _admin_user(db: AsyncSession, user_id: uuid.UUID) -> AppUser:
    status = await db.scalar(select(PlatformAdmin.status).where(PlatformAdmin.user_id == user_id))
    user = await db.get(AppUser, user_id)
    if status != PlatformAdminStatus.ACTIVE or user is None:
        raise AppError(
            403, "FORBIDDEN", "Multi-factor authentication is for platform administrators"
        )
    return user


async def _reauthenticate(
    db: AsyncSession, passwords: PasswordService, user: AppUser, password: str
) -> None:
    """Strong re-authentication for enrolment changes; failures feed the login throttle."""
    now = clock.now()
    key = throttle.account_key(user.email_normalized)
    if await throttle.is_locked(db, {ThrottleScope.ACCOUNT: key}, now):
        raise TooManyAttemptsError
    if not passwords.verify(user.password_hash, password):
        await throttle.register_failure(db, ThrottleScope.ACCOUNT, key, now)
        record(db, AuditAction.MFA_REAUTH_FAILED, actor_user_id=user.id)
        await db.commit()
        raise InvalidCredentialsError


async def status(
    db: AsyncSession, settings: Settings, user_id: uuid.UUID, pending: str | None
) -> MfaStatus:
    enabled = await mfa.confirmed_mfa(db, user_id) is not None
    left = await mfa.recovery_codes_left(db, user_id) if enabled else 0
    return MfaStatus(enabled, settings.require_admin_mfa, pending, left)


async def start_enrollment(
    db: AsyncSession,
    passwords: PasswordService,
    cipher: mfa.MfaCipher,
    *,
    user_id: uuid.UUID,
    password: str,
) -> Enrollment:
    user = await _admin_user(db, user_id)
    if await mfa.confirmed_mfa(db, user_id) is not None:
        raise AppError(409, "MFA_ALREADY_ENABLED", "Multi-factor authentication is already on")
    await _reauthenticate(db, passwords, user, password)
    secret = mfa.new_secret()
    key_id, ciphertext = cipher.seal(user_id, secret)
    now = clock.now()
    await db.execute(
        insert(AdminMfa)
        .values(
            user_id=user_id,
            secret_ciphertext=ciphertext,
            secret_key_id=key_id,
            confirmed_at=None,
            last_used_step=None,
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_update(
            index_elements=["user_id"],
            set_={"secret_ciphertext": ciphertext, "secret_key_id": key_id, "updated_at": now},
        )
    )
    record(db, AuditAction.MFA_ENROLLMENT_STARTED, actor_user_id=user_id, actor_plane="PLATFORM")
    await db.commit()
    return Enrollment(secret, mfa.otpauth_uri(secret, user.email))


async def confirm_enrollment(
    db: AsyncSession,
    settings: Settings,
    cipher: mfa.MfaCipher,
    *,
    user_id: uuid.UUID,
    session_id: uuid.UUID,
    code: str,
) -> tuple[list[str], IssuedSession]:
    await _admin_user(db, user_id)
    row = await db.scalar(
        select(AdminMfa)
        .where(AdminMfa.user_id == user_id, AdminMfa.confirmed_at.is_(None))
        .with_for_update()
    )
    if row is None:
        raise AppError(409, "MFA_NOT_ENROLLING", "Start enrolment first")
    now = clock.now()
    secret = cipher.open(user_id, row.secret_key_id, row.secret_ciphertext)
    step = mfa.matching_step(secret, code, now, None)
    if step is None:
        raise mfa.invalid_code()
    row.confirmed_at = now
    row.last_used_step = step
    codes = await mfa.replace_recovery_codes(db, user_id, now)
    revoked = await revoke_user_sessions(db, user_id, now)  # every earlier session, incl. this one
    issued = await create_session(db, user_id, now, settings)
    record(
        db,
        AuditAction.MFA_ENABLED,
        actor_user_id=user_id,
        actor_plane="PLATFORM",
        entity_kind="session",
        entity_id=issued.session_id,
        details={"sessions_revoked": revoked, "replaced_session": str(session_id)},
    )
    await db.commit()
    return codes, issued


async def verify_login(
    db: AsyncSession,
    settings: Settings,
    cipher: mfa.MfaCipher,
    *,
    user_id: uuid.UUID,
    session_id: uuid.UUID,
    code: str | None,
    recovery_code: str | None,
) -> IssuedSession:
    session = await db.scalar(
        select(UserSession).where(UserSession.id == session_id).with_for_update()
    )
    user = await db.get(AppUser, user_id)
    if session is None or user is None or session.mfa_pending != mfa.VERIFY:
        raise AppError(409, "MFA_NOT_PENDING", "This session does not need a code")
    now = clock.now()
    key = throttle.account_key(user.email_normalized)
    if await throttle.is_locked(db, {ThrottleScope.ACCOUNT: key}, now):
        raise TooManyAttemptsError
    method = "totp"
    ok = False
    if code:
        ok = await mfa.verify_totp(db, cipher, user_id, code, now)
    elif recovery_code:
        method = "recovery_code"
        ok = await mfa.consume_recovery_code(db, user_id, recovery_code, now)
    if not ok:
        session.mfa_failures += 1
        await throttle.register_failure(db, ThrottleScope.ACCOUNT, key, now)
        if session.mfa_failures >= mfa.MAX_PENDING_FAILURES:
            await revoke_session(db, session.id, now)
        record(
            db,
            AuditAction.MFA_FAILED,
            actor_user_id=user_id,
            entity_kind="session",
            entity_id=session.id,
            details={"method": method, "failures": session.mfa_failures},
        )
        await db.commit()
        raise mfa.invalid_code()
    await throttle.reset(db, ThrottleScope.ACCOUNT, key)
    await revoke_session(db, session.id, now)  # rotate: the pending session never gains access
    issued = await create_session(db, user_id, now, settings)
    details: dict[str, object] = {"method": method}
    if method == "recovery_code":
        details["recovery_codes_left"] = await mfa.recovery_codes_left(db, user_id)
    record(
        db,
        AuditAction.MFA_VERIFIED,
        actor_user_id=user_id,
        entity_kind="session",
        entity_id=issued.session_id,
        details=details,
    )
    await db.commit()
    return issued


async def _reauth_with_code(
    db: AsyncSession,
    passwords: PasswordService,
    cipher: mfa.MfaCipher,
    user: AppUser,
    password: str,
    code: str,
) -> None:
    await _reauthenticate(db, passwords, user, password)
    if not await mfa.verify_totp(db, cipher, user.id, code, clock.now()):
        await throttle.register_failure(
            db, ThrottleScope.ACCOUNT, throttle.account_key(user.email_normalized), clock.now()
        )
        record(db, AuditAction.MFA_FAILED, actor_user_id=user.id, details={"method": "totp"})
        await db.commit()
        raise mfa.invalid_code()


async def regenerate_codes(
    db: AsyncSession,
    passwords: PasswordService,
    cipher: mfa.MfaCipher,
    *,
    user_id: uuid.UUID,
    password: str,
    code: str,
) -> list[str]:
    user = await _admin_user(db, user_id)
    await _reauth_with_code(db, passwords, cipher, user, password, code)
    codes = await mfa.replace_recovery_codes(db, user_id, clock.now())
    record(
        db, AuditAction.MFA_RECOVERY_CODES_REPLACED, actor_user_id=user_id, actor_plane="PLATFORM"
    )
    await db.commit()
    return codes


async def disable(
    db: AsyncSession,
    settings: Settings,
    passwords: PasswordService,
    cipher: mfa.MfaCipher,
    *,
    user_id: uuid.UUID,
    session_id: uuid.UUID,
    password: str,
    code: str,
) -> None:
    if settings.require_admin_mfa:
        raise AppError(409, "MFA_REQUIRED_BY_POLICY", "Multi-factor authentication is required")
    user = await _admin_user(db, user_id)
    await _reauth_with_code(db, passwords, cipher, user, password, code)
    await _remove(db, user_id)
    revoked = await revoke_user_sessions(db, user_id, clock.now(), keep=session_id)
    record(
        db,
        AuditAction.MFA_DISABLED,
        actor_user_id=user_id,
        actor_plane="PLATFORM",
        details={"sessions_revoked": revoked},
    )
    await db.commit()


async def _remove(db: AsyncSession, user_id: uuid.UUID) -> None:
    await db.execute(delete(AdminRecoveryCode).where(AdminRecoveryCode.user_id == user_id))
    await db.execute(delete(AdminMfa).where(AdminMfa.user_id == user_id))


async def operator_reset(db: AsyncSession, *, email: str) -> None:
    """CLI recovery for a SYSTEM_ADMIN who lost their authenticator and recovery codes: remove
    MFA and revoke every session. If the policy requires MFA, the next login must enrol again.
    Requires host shell access to the deployment; audited."""
    user = await db.scalar(
        select(AppUser).where(AppUser.email_normalized == normalize_email(email))
    )
    if user is None:
        raise AppError(404, "NOT_FOUND", "No such platform administrator")
    await _admin_user(db, user.id)
    await _remove(db, user.id)
    revoked = await revoke_user_sessions(db, user.id, clock.now())
    record(
        db,
        AuditAction.MFA_RESET_BY_OPERATOR,
        actor_kind="CLI",
        entity_kind="user",
        entity_id=user.id,
        details={"sessions_revoked": revoked},
    )
    await db.commit()
