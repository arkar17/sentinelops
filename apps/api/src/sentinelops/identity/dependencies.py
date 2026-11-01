"""Authentication and CSRF dependencies shared by every authenticated route."""

import hmac
import ipaddress
import uuid
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Request

from sentinelops import clock
from sentinelops.config import Settings
from sentinelops.db.session import DbSession
from sentinelops.errors import AppError
from sentinelops.identity.passwords import PasswordService
from sentinelops.identity.sessions import CSRF_HEADER, resolve_session, session_cookie_name
from sentinelops.identity.tokens import hash_token
from sentinelops.mail import Mailer

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    email: str
    session_id: uuid.UUID
    csrf_secret_hash: str
    mfa_pending: str | None = None  # VERIFY/ENROLL: MFA not yet completed (OD-01)


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_passwords(request: Request) -> PasswordService:
    passwords: PasswordService = request.app.state.passwords
    return passwords


def get_mailer(request: Request) -> Mailer:
    mailer: Mailer = request.app.state.mailer
    return mailer


AppSettings = Annotated[Settings, Depends(get_settings_dep)]
Passwords = Annotated[PasswordService, Depends(get_passwords)]
AppMailer = Annotated[Mailer, Depends(get_mailer)]


class UnauthenticatedError(AppError):
    def __init__(self) -> None:
        super().__init__(401, "UNAUTHENTICATED", "Authentication required")


async def get_optional_principal(
    request: Request, db: DbSession, settings: AppSettings
) -> Principal | None:
    token = request.cookies.get(session_cookie_name(settings))
    if not token:
        return None
    resolved = await resolve_session(db, token, clock.now(), settings)
    if resolved is None:
        return None
    session, user = resolved
    if db.dirty:  # last_seen_at was touched
        await db.commit()
    principal = Principal(
        user.id, user.email, session.id, session.csrf_secret_hash, session.mfa_pending
    )
    _enforce_csrf(request, principal)
    return principal


async def get_pending_principal(
    principal: Annotated[Principal | None, Depends(get_optional_principal)],
) -> Principal:
    """Any signed-in session, including one that has not completed MFA. Only /api/auth/me,
    /api/auth/logout and /api/auth/mfa/* accept these."""
    if principal is None:
        raise UnauthenticatedError
    return principal


async def get_principal(
    principal: Annotated[Principal, Depends(get_pending_principal)],
) -> Principal:
    if principal.mfa_pending == "VERIFY":
        raise AppError(401, "MFA_REQUIRED", "Enter your authentication code to continue")
    if principal.mfa_pending == "ENROLL":
        raise AppError(403, "MFA_ENROLLMENT_REQUIRED", "Set up multi-factor authentication first")
    return principal


def _enforce_csrf(request: Request, principal: Principal) -> None:
    """Session-authenticated unsafe requests must echo the session's CSRF token."""
    if request.method not in UNSAFE_METHODS:
        return
    supplied = request.headers.get(CSRF_HEADER, "")
    if not supplied or not hmac.compare_digest(hash_token(supplied), principal.csrf_secret_hash):
        raise AppError(403, "CSRF_FAILED", "Missing or invalid CSRF token")


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
PendingPrincipal = Annotated[Principal, Depends(get_pending_principal)]
OptionalPrincipal = Annotated[Principal | None, Depends(get_optional_principal)]


def client_ip(request: Request) -> str:
    """The client address for throttling and rate limits.

    X-Forwarded-For is honoured only when the socket peer is a configured trusted proxy; the
    header is then read right to left, skipping trusted proxies, and the first other valid
    address is the client. Spoofed headers from untrusted peers are ignored."""
    peer = request.client.host if request.client else "unknown"
    settings: Settings = request.app.state.settings
    networks = _trusted_networks(tuple(settings.trusted_proxies))
    if not networks or not _in(peer, networks):
        return peer
    forwarded = ",".join(request.headers.getlist("x-forwarded-for"))
    for hop in reversed([h.strip() for h in forwarded.split(",") if h.strip()]):
        try:
            address = ipaddress.ip_address(hop)
        except ValueError:
            return peer  # malformed chain: fall back to the proxy itself
        if not any(address in net for net in networks):
            return str(address)
    return peer


@lru_cache(maxsize=8)
def _trusted_networks(
    entries: tuple[str, ...],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(e, strict=False) for e in entries)


def _in(host: str, networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in net for net in networks)
