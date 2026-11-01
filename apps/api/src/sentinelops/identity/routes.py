"""Authentication routes under /api/auth (02_TECHNICAL_ARCHITECTURE.md §9)."""

import logging

from fastapi import APIRouter, BackgroundTasks, Request, Response, status

from sentinelops.db.session import DbSession
from sentinelops.identity import service
from sentinelops.identity.dependencies import (
    AppMailer,
    AppSettings,
    CurrentPrincipal,
    Passwords,
    PendingPrincipal,
    client_ip,
)
from sentinelops.identity.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    PasswordResetRequest,
    RevokedCount,
    SessionOut,
    TokenPasswordRequest,
    UserOut,
)
from sentinelops.identity.sessions import (
    clear_session_cookies,
    session_cookie_name,
    set_session_cookies,
)
from sentinelops.mail import MailDeliveryError, Mailer, OutgoingEmail

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=UserOut)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: DbSession,
    passwords: Passwords,
    settings: AppSettings,
) -> UserOut:
    result = await service.login(
        db,
        passwords,
        settings,
        email=body.email,
        password=body.password,
        client_ip=client_ip(request),
        previous_session_token=request.cookies.get(session_cookie_name(settings)),
    )
    set_session_cookies(response, result.session, settings)
    return UserOut(
        id=result.user.id,
        email=result.user.email,
        status=result.user.status,
        mfa_pending=result.mfa_pending,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response, principal: PendingPrincipal, db: DbSession, settings: AppSettings
) -> None:
    await service.logout(db, user_id=principal.user_id, session_id=principal.session_id)
    clear_session_cookies(response, settings)


@router.post("/activate", status_code=status.HTTP_204_NO_CONTENT)
async def activate(body: TokenPasswordRequest, db: DbSession, passwords: Passwords) -> None:
    await service.activate_account(db, passwords, token=body.token, password=body.password)


async def _send_quietly(mailer: Mailer, message: OutgoingEmail) -> None:
    try:
        await mailer.send(message)
    except MailDeliveryError:
        logger.warning("Password reset email could not be delivered")


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
async def request_password_reset(
    body: PasswordResetRequest,
    background: BackgroundTasks,
    db: DbSession,
    mailer: AppMailer,
    settings: AppSettings,
) -> dict[str, str]:
    """Always 202 with the same body, whether or not the account exists (no enumeration)."""
    issued = await service.request_password_reset(db, email=body.email)
    if issued is not None:
        user, token = issued
        link = f"{settings.public_base_url}/reset-password#token={token}"
        message = OutgoingEmail(
            to=user.email,
            subject="Reset your SentinelOps password",
            body=(
                "A password reset was requested for your SentinelOps account.\n\n"
                f"Reset your password within 30 minutes: {link}\n\n"
                "If you did not request this, ignore this email."
            ),
        )
        background.add_task(_send_quietly, mailer, message)
    return {"status": "accepted"}


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_password_reset(
    body: TokenPasswordRequest, db: DbSession, passwords: Passwords
) -> None:
    await service.reset_password(db, passwords, token=body.token, password=body.password)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: ChangePasswordRequest,
    response: Response,
    principal: CurrentPrincipal,
    db: DbSession,
    passwords: Passwords,
    settings: AppSettings,
) -> None:
    issued = await service.change_password(
        db,
        passwords,
        settings,
        user_id=principal.user_id,
        current_password=body.current_password,
        new_password=body.new_password,
    )
    set_session_cookies(response, issued, settings)


@router.get("/sessions", response_model=list[SessionOut])
async def list_sessions(principal: CurrentPrincipal, db: DbSession) -> list[SessionOut]:
    rows = await service.list_sessions(db, user_id=principal.user_id)
    return [
        SessionOut(
            id=row.id,
            created_at=row.created_at,
            last_seen_at=row.last_seen_at,
            expires_at=row.expires_at,
            current=row.id == principal.session_id,
        )
        for row in rows
    ]


@router.post("/sessions/revoke-others", response_model=RevokedCount)
async def revoke_other_sessions(principal: CurrentPrincipal, db: DbSession) -> RevokedCount:
    revoked = await service.revoke_other_sessions(
        db, user_id=principal.user_id, current_session_id=principal.session_id
    )
    return RevokedCount(revoked=revoked)
