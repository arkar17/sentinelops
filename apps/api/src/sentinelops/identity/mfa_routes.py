"""SYSTEM_ADMIN MFA routes under /api/auth/mfa (OD-01). Responses that carry a secret or recovery
codes are marked no-store; nothing here is logged."""

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from sentinelops.db.session import DbSession
from sentinelops.identity import mfa, mfa_service
from sentinelops.identity.dependencies import (
    AppSettings,
    CurrentPrincipal,
    Passwords,
    PendingPrincipal,
)
from sentinelops.identity.passwords import MAX_PASSWORD_LENGTH
from sentinelops.identity.sessions import set_session_cookies

router = APIRouter(prefix="/api/auth/mfa", tags=["auth"])

Code = Field(min_length=6, max_length=10)


def _cipher(request: Request) -> mfa.MfaCipher:
    cipher: mfa.MfaCipher = request.app.state.mfa_cipher
    return cipher


class PasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class CodeIn(BaseModel):
    code: str = Code


class VerifyIn(BaseModel):
    code: str | None = Field(default=None, min_length=6, max_length=10)
    recovery_code: str | None = Field(default=None, min_length=8, max_length=20)


class PasswordCodeIn(PasswordIn):
    code: str = Code


class StatusOut(BaseModel):
    enabled: bool
    required: bool
    pending: str | None
    recovery_codes_left: int


class EnrollmentOut(BaseModel):
    secret: str
    otpauth_uri: str


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


@router.get("", response_model=StatusOut)
async def get_status(
    principal: PendingPrincipal, db: DbSession, settings: AppSettings
) -> StatusOut:
    data = await mfa_service.status(db, settings, principal.user_id, principal.mfa_pending)
    return StatusOut(**data.__dict__)


@router.post("/enroll", response_model=EnrollmentOut)
async def enroll(
    body: PasswordIn,
    request: Request,
    response: Response,
    principal: PendingPrincipal,
    db: DbSession,
    passwords: Passwords,
) -> EnrollmentOut:
    _no_store(response)
    result = await mfa_service.start_enrollment(
        db,
        passwords,
        _cipher(request),
        user_id=principal.user_id,
        password=body.current_password,
    )
    return EnrollmentOut(secret=result.secret, otpauth_uri=result.otpauth_uri)


@router.post("/enroll/confirm", response_model=RecoveryCodesOut)
async def confirm(
    body: CodeIn,
    request: Request,
    response: Response,
    principal: PendingPrincipal,
    db: DbSession,
    settings: AppSettings,
) -> RecoveryCodesOut:
    _no_store(response)
    codes, issued = await mfa_service.confirm_enrollment(
        db,
        settings,
        _cipher(request),
        user_id=principal.user_id,
        session_id=principal.session_id,
        code=body.code,
    )
    set_session_cookies(response, issued, settings)
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/verify", status_code=204)
async def verify(
    body: VerifyIn,
    request: Request,
    response: Response,
    principal: PendingPrincipal,
    db: DbSession,
    settings: AppSettings,
) -> None:
    issued = await mfa_service.verify_login(
        db,
        settings,
        _cipher(request),
        user_id=principal.user_id,
        session_id=principal.session_id,
        code=body.code,
        recovery_code=body.recovery_code,
    )
    set_session_cookies(response, issued, settings)


@router.post("/recovery-codes", response_model=RecoveryCodesOut)
async def regenerate(
    body: PasswordCodeIn,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    db: DbSession,
    passwords: Passwords,
) -> RecoveryCodesOut:
    _no_store(response)
    codes = await mfa_service.regenerate_codes(
        db,
        passwords,
        _cipher(request),
        user_id=principal.user_id,
        password=body.current_password,
        code=body.code,
    )
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/disable", status_code=204)
async def disable(
    body: PasswordCodeIn,
    request: Request,
    principal: CurrentPrincipal,
    db: DbSession,
    settings: AppSettings,
    passwords: Passwords,
) -> None:
    await mfa_service.disable(
        db,
        settings,
        passwords,
        _cipher(request),
        user_id=principal.user_id,
        session_id=principal.session_id,
        password=body.current_password,
        code=body.code,
    )
