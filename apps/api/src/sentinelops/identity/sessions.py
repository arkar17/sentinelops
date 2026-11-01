"""Server-side sessions and their cookies.

The session cookie is HttpOnly. The CSRF cookie is readable by the web app, which echoes it in
the X-CSRF-Token header; the server compares the header with the hash stored on the session.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import Response
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.config import Settings
from sentinelops.identity.models import AppUser, UserSession, UserStatus
from sentinelops.identity.tokens import hash_token, new_token

CSRF_HEADER = "X-CSRF-Token"
# Touch last_seen_at at most this often to avoid a write on every request.
_TOUCH_INTERVAL = timedelta(seconds=60)


@dataclass(frozen=True)
class IssuedSession:
    session_id: uuid.UUID
    token: str
    csrf_token: str
    expires_at: datetime


def session_cookie_name(settings: Settings) -> str:
    return "__Host-sentinelops_session" if settings.secure_cookies else "sentinelops_session"


def csrf_cookie_name(settings: Settings) -> str:
    return "__Host-sentinelops_csrf" if settings.secure_cookies else "sentinelops_csrf"


async def create_session(
    db: AsyncSession,
    user_id: uuid.UUID,
    now: datetime,
    settings: Settings,
    *,
    mfa_pending: str | None = None,
) -> IssuedSession:
    token, csrf_token = new_token(), new_token()
    expires_at = now + timedelta(hours=settings.session_absolute_hours)
    row = UserSession(
        user_id=user_id,
        token_hash=hash_token(token),
        csrf_secret_hash=hash_token(csrf_token),
        created_at=now,
        last_seen_at=now,
        expires_at=expires_at,
        mfa_pending=mfa_pending,
        mfa_failures=0,
    )
    db.add(row)
    await db.flush()
    return IssuedSession(row.id, token, csrf_token, expires_at)


async def resolve_session(
    db: AsyncSession, token: str, now: datetime, settings: Settings
) -> tuple[UserSession, AppUser] | None:
    """Return the live session and its ACTIVE user, or None if expired, idle, revoked or unknown."""
    row = (
        await db.execute(
            select(UserSession, AppUser)
            .join(AppUser, AppUser.id == UserSession.user_id)
            .where(UserSession.token_hash == hash_token(token))
        )
    ).one_or_none()
    if row is None:
        return None
    session, user = row
    idle_limit = timedelta(minutes=settings.session_idle_minutes)
    if (
        session.revoked_at is not None
        or session.expires_at <= now
        or session.last_seen_at + idle_limit <= now
        or user.status != UserStatus.ACTIVE
    ):
        return None
    if now - session.last_seen_at >= _TOUCH_INTERVAL:
        session.last_seen_at = now
    return session, user


async def revoke_session(db: AsyncSession, session_id: uuid.UUID, now: datetime) -> None:
    await db.execute(
        update(UserSession)
        .where(UserSession.id == session_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )


async def revoke_user_sessions(
    db: AsyncSession, user_id: uuid.UUID, now: datetime, *, keep: uuid.UUID | None = None
) -> int:
    stmt = (
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    if keep is not None:
        stmt = stmt.where(UserSession.id != keep)
    result = await db.execute(stmt)
    return int(getattr(result, "rowcount", 0) or 0)


def set_session_cookies(response: Response, issued: IssuedSession, settings: Settings) -> None:
    max_age = settings.session_absolute_hours * 3600
    secure = settings.secure_cookies
    response.set_cookie(
        session_cookie_name(settings),
        issued.token,
        max_age=max_age,
        path="/",
        secure=secure,
        httponly=True,
        samesite="lax",
    )
    response.set_cookie(
        csrf_cookie_name(settings),
        issued.csrf_token,
        max_age=max_age,
        path="/",
        secure=secure,
        httponly=False,
        samesite="lax",
    )


def clear_session_cookies(response: Response, settings: Settings) -> None:
    for name, httponly in (
        (session_cookie_name(settings), True),
        (csrf_cookie_name(settings), False),
    ):
        response.delete_cookie(
            name, path="/", secure=settings.secure_cookies, httponly=httponly, samesite="lax"
        )
