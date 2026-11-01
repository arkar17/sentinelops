"""Authentication use cases. Each function commits its own transaction.

Failure paths that must leave an audit trail commit before raising.
"""

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.config import Settings
from sentinelops.errors import AppError
from sentinelops.identity import mfa, throttle
from sentinelops.identity.emails import normalize_email
from sentinelops.identity.models import (
    AppUser,
    AuthToken,
    ThrottleScope,
    TokenPurpose,
    UserSession,
    UserStatus,
)
from sentinelops.identity.passwords import PasswordService, validate_new_password
from sentinelops.identity.sessions import (
    IssuedSession,
    create_session,
    revoke_session,
    revoke_user_sessions,
)
from sentinelops.identity.tokens import hash_token, new_token
from sentinelops.platform.models import PlatformAdmin, PlatformAdminStatus

ACTIVATION_TOKEN_TTL = timedelta(minutes=30)  # FR-PLT-001
PASSWORD_RESET_TOKEN_TTL = timedelta(minutes=30)  # FR-ID-006
MAX_RESET_REQUESTS_PER_WINDOW = 3
RESET_REQUEST_WINDOW = timedelta(minutes=15)


class InvalidCredentialsError(AppError):
    def __init__(self) -> None:
        super().__init__(401, "INVALID_CREDENTIALS", "Invalid email or password")


class TooManyAttemptsError(AppError):
    def __init__(self) -> None:
        super().__init__(429, "TOO_MANY_ATTEMPTS", "Too many sign-in attempts. Try again later.")


class InvalidTokenError(AppError):
    def __init__(self) -> None:
        super().__init__(400, "INVALID_TOKEN", "This link is invalid or has expired")


@dataclass(frozen=True)
class LoginResult:
    user: AppUser
    session: IssuedSession
    mfa_pending: str | None = None


async def login(
    db: AsyncSession,
    passwords: PasswordService,
    settings: Settings,
    *,
    email: str,
    password: str,
    client_ip: str,
    previous_session_token: str | None = None,
) -> LoginResult:
    now = clock.now()
    email_normalized = normalize_email(email)
    keys = {
        ThrottleScope.ACCOUNT: throttle.account_key(email_normalized),
        ThrottleScope.IP: throttle.ip_key(client_ip),
    }
    user = await db.scalar(select(AppUser).where(AppUser.email_normalized == email_normalized))
    actor_id = user.id if user else None

    if await throttle.is_locked(db, keys, now):
        record(db, AuditAction.LOGIN_THROTTLED, actor_user_id=actor_id)
        await db.commit()
        raise TooManyAttemptsError

    usable = user is not None and user.status == UserStatus.ACTIVE
    verified = passwords.verify(user.password_hash if usable and user else None, password)
    if not (usable and verified) or user is None:
        for scope, key in keys.items():
            await throttle.register_failure(db, scope, key, now)
        reason = "unknown_account" if user is None else ("bad_password" if usable else "inactive")
        record(db, AuditAction.LOGIN_FAILED, actor_user_id=actor_id, details={"reason": reason})
        await db.commit()
        raise InvalidCredentialsError

    await throttle.reset(db, ThrottleScope.ACCOUNT, keys[ThrottleScope.ACCOUNT])
    if user.password_hash and passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash(password)
    user.last_login_at = now
    if previous_session_token:  # session rotation: the pre-login session never survives login
        await db.execute(
            update(UserSession)
            .where(
                UserSession.token_hash == hash_token(previous_session_token),
                UserSession.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
    is_admin = (
        await db.scalar(select(PlatformAdmin.status).where(PlatformAdmin.user_id == user.id))
        == PlatformAdminStatus.ACTIVE
    )
    pending = await mfa.login_requirement(db, user.id, settings, is_admin=is_admin)
    issued = await create_session(db, user.id, now, settings, mfa_pending=pending)
    record(
        db,
        AuditAction.LOGIN_SUCCEEDED,
        actor_user_id=user.id,
        entity_kind="session",
        entity_id=issued.session_id,
        details={"mfa_pending": pending} if pending else None,
    )
    await db.commit()
    return LoginResult(user, issued, pending)


async def logout(db: AsyncSession, *, user_id: uuid.UUID, session_id: uuid.UUID) -> None:
    await revoke_session(db, session_id, clock.now())
    record(
        db, AuditAction.LOGOUT, actor_user_id=user_id, entity_kind="session", entity_id=session_id
    )
    await db.commit()


async def issue_token(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    purpose: str,
    ttl: timedelta,
    created_by: uuid.UUID | None = None,
) -> str:
    """Create a single-use token, invalidating earlier unused tokens of the same purpose."""
    now = clock.now()
    await db.execute(
        update(AuthToken)
        .where(
            AuthToken.user_id == user_id,
            AuthToken.purpose == purpose,
            AuthToken.used_at.is_(None),
        )
        .values(used_at=now)
    )
    token = new_token()
    db.add(
        AuthToken(
            user_id=user_id,
            purpose=purpose,
            token_hash=hash_token(token),
            expires_at=now + ttl,
            created_by=created_by,
            created_at=now,
        )
    )
    return token


async def _lock_valid_token(
    db: AsyncSession, token: str, purpose: str
) -> tuple[AuthToken, AppUser]:
    row = (
        await db.execute(
            select(AuthToken, AppUser)
            .join(AppUser, AppUser.id == AuthToken.user_id)
            .where(AuthToken.token_hash == hash_token(token), AuthToken.purpose == purpose)
            .with_for_update(of=AuthToken)
        )
    ).one_or_none()
    if row is None:
        raise InvalidTokenError
    auth_token, user = row
    if auth_token.used_at is not None or auth_token.expires_at <= clock.now():
        raise InvalidTokenError
    return auth_token, user


async def activate_account(
    db: AsyncSession, passwords: PasswordService, *, token: str, password: str
) -> None:
    auth_token, user = await _lock_valid_token(db, token, TokenPurpose.ACTIVATION)
    if user.status != UserStatus.PENDING_ACTIVATION:
        raise InvalidTokenError
    validate_new_password(password, user.email)
    now = clock.now()
    auth_token.used_at = now
    user.password_hash = passwords.hash(password)
    user.status = UserStatus.ACTIVE
    user.email_verified_at = user.email_verified_at or now
    user.version += 1
    await revoke_user_sessions(db, user.id, now)
    record(
        db,
        AuditAction.ACCOUNT_ACTIVATED,
        actor_user_id=user.id,
        entity_kind="user",
        entity_id=user.id,
    )
    await db.commit()


async def request_password_reset(db: AsyncSession, *, email: str) -> tuple[AppUser, str] | None:
    """Return (user, token) for an ACTIVE account, else None. Callers respond identically."""
    user = await db.scalar(
        select(AppUser).where(AppUser.email_normalized == normalize_email(email))
    )
    if user is None or user.status != UserStatus.ACTIVE:
        return None
    window_start = clock.now() - RESET_REQUEST_WINDOW
    recent = await db.scalar(
        select(AuthToken.id)
        .where(
            AuthToken.user_id == user.id,
            AuthToken.purpose == TokenPurpose.PASSWORD_RESET,
            AuthToken.created_at > window_start,
        )
        .offset(MAX_RESET_REQUESTS_PER_WINDOW - 1)
        .limit(1)
    )
    if recent is not None:
        return None
    token = await issue_token(
        db, user_id=user.id, purpose=TokenPurpose.PASSWORD_RESET, ttl=PASSWORD_RESET_TOKEN_TTL
    )
    record(
        db,
        AuditAction.PASSWORD_RESET_REQUESTED,
        actor_user_id=user.id,
        entity_kind="user",
        entity_id=user.id,
    )
    await db.commit()
    return user, token


async def reset_password(
    db: AsyncSession, passwords: PasswordService, *, token: str, password: str
) -> None:
    auth_token, user = await _lock_valid_token(db, token, TokenPurpose.PASSWORD_RESET)
    if user.status != UserStatus.ACTIVE:
        raise InvalidTokenError
    validate_new_password(password, user.email)
    now = clock.now()
    auth_token.used_at = now
    user.password_hash = passwords.hash(password)
    user.version += 1
    revoked = await revoke_user_sessions(db, user.id, now)
    await throttle.reset(db, ThrottleScope.ACCOUNT, throttle.account_key(user.email_normalized))
    record(
        db,
        AuditAction.PASSWORD_RESET_COMPLETED,
        actor_user_id=user.id,
        entity_kind="user",
        entity_id=user.id,
        details={"sessions_revoked": revoked},
    )
    await db.commit()


async def change_password(
    db: AsyncSession,
    passwords: PasswordService,
    settings: Settings,
    *,
    user_id: uuid.UUID,
    current_password: str,
    new_password: str,
) -> IssuedSession:
    """Change password, revoke every session and issue a fresh one (rotation)."""
    user = await db.get(AppUser, user_id, with_for_update=True)
    if user is None or not passwords.verify(user.password_hash, current_password):
        raise AppError(400, "CURRENT_PASSWORD_INCORRECT", "Current password is incorrect")
    validate_new_password(new_password, user.email)
    now = clock.now()
    user.password_hash = passwords.hash(new_password)
    user.version += 1
    revoked = await revoke_user_sessions(db, user.id, now)
    issued = await create_session(db, user.id, now, settings)
    record(
        db,
        AuditAction.PASSWORD_CHANGED,
        actor_user_id=user.id,
        entity_kind="user",
        entity_id=user.id,
        details={"sessions_revoked": revoked},
    )
    await db.commit()
    return issued


async def list_sessions(db: AsyncSession, *, user_id: uuid.UUID) -> list[UserSession]:
    now = clock.now()
    rows = await db.scalars(
        select(UserSession)
        .where(
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now,
        )
        .order_by(UserSession.created_at.desc())
    )
    return list(rows)


async def revoke_other_sessions(
    db: AsyncSession, *, user_id: uuid.UUID, current_session_id: uuid.UUID
) -> int:
    revoked = await revoke_user_sessions(db, user_id, clock.now(), keep=current_session_id)
    record(
        db,
        AuditAction.SESSIONS_REVOKED,
        actor_user_id=user_id,
        details={"sessions_revoked": revoked},
    )
    await db.commit()
    return revoked
