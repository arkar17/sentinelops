"""GET /api/auth/me: composes identity with the platform plane flag (entrypoint layer)."""

import uuid

from fastapi import APIRouter
from pydantic import BaseModel

from sentinelops.db.session import DbSession
from sentinelops.identity.dependencies import PendingPrincipal
from sentinelops.platform.service import is_active_platform_admin

router = APIRouter(prefix="/api/auth", tags=["auth"])


class MeOut(BaseModel):
    id: uuid.UUID
    email: str
    is_platform_admin: bool
    mfa_pending: str | None = None  # VERIFY or ENROLL until MFA is completed (OD-01)


@router.get("/me", response_model=MeOut)
async def me(principal: PendingPrincipal, db: DbSession) -> MeOut:
    return MeOut(
        id=principal.user_id,
        email=principal.email,
        is_platform_admin=await is_active_platform_admin(db, principal.user_id),
        mfa_pending=principal.mfa_pending,
    )
