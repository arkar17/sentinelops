"""SYSTEM_ADMIN organization routes (/api/admin/organizations). Metadata only (FR-PLT-006)."""

import uuid
from dataclasses import asdict
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from sentinelops.db.session import DbSession
from sentinelops.errors import AppError
from sentinelops.identity.dependencies import AppMailer, AppSettings, Principal
from sentinelops.platform import organizations
from sentinelops.platform.dependencies import PlatformPermission
from sentinelops.tenancy.routes import send_invitation_email

router = APIRouter(prefix="/api/admin/organizations", tags=["platform"])


def Admin(action: str) -> Any:  # noqa: N802  # reads like a type in signatures
    return Depends(PlatformPermission(action))


class LimitsOut(BaseModel):
    max_monitors: int
    min_interval_seconds: int
    max_status_pages: int
    max_channels: int


class OrgMetadataOut(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    timezone: str
    status: str
    suspended_at: datetime | None
    suspended_reason: str | None
    created_at: datetime
    version: int
    owner_emails: list[str]
    member_count: int
    project_count: int
    pending_owner_invitation: bool
    limit_overrides: dict[str, int | None]
    effective_limits: LimitsOut


class OrgCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    slug: str = Field(min_length=3, max_length=48)
    timezone: str = Field(default="UTC", min_length=1, max_length=64)
    owner_email: str = Field(min_length=3, max_length=254)


class OrgPatch(BaseModel):
    version: int
    name: str | None = Field(default=None, min_length=1, max_length=120)
    slug: str | None = Field(default=None, min_length=3, max_length=48)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)


class SuspendIn(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class LimitsIn(BaseModel):
    """Overrides; null restores the platform default. Ranges match the platform settings."""

    max_monitors: int | None = Field(default=None, ge=1, le=10000)
    min_interval_seconds: int | None = Field(default=None, ge=60, le=300)
    max_status_pages: int | None = Field(default=None, ge=0, le=100)
    max_channels: int | None = Field(default=None, ge=0, le=100)


class OwnerInviteIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)


def _out(meta: organizations.OrgMetadata) -> OrgMetadataOut:
    return OrgMetadataOut(**asdict(meta))


@router.get("", response_model=list[OrgMetadataOut])
async def list_organizations(
    db: DbSession, _admin: Annotated[Principal, Admin("PLT.org.list")]
) -> list[OrgMetadataOut]:
    return [_out(m) for m in await organizations.list_organizations(db)]


@router.post("", response_model=OrgMetadataOut, status_code=status.HTTP_201_CREATED)
async def create_organization(
    body: OrgCreate,
    db: DbSession,
    mailer: AppMailer,
    settings: AppSettings,
    admin: Annotated[Principal, Admin("PLT.org.create")],
) -> OrgMetadataOut:
    meta, invitation, token = await organizations.create_organization(
        db,
        actor_id=admin.user_id,
        name=body.name.strip(),
        slug=body.slug,
        timezone=body.timezone,
        owner_email=body.owner_email,
    )
    await send_invitation_email(
        mailer,
        to=invitation.email_normalized,
        organization=meta.name,
        role=invitation.role,
        link=f"{settings.public_base_url}/accept-invite#token={token}",
        inviter="The SentinelOps platform team",
    )
    return _out(meta)


@router.get("/{org_id}", response_model=OrgMetadataOut)
async def get_organization(
    org_id: uuid.UUID, db: DbSession, _admin: Annotated[Principal, Admin("PLT.org.view")]
) -> OrgMetadataOut:
    return _out(await organizations.get_organization(db, org_id))


@router.patch("/{org_id}", response_model=OrgMetadataOut)
async def update_organization(
    org_id: uuid.UUID,
    body: OrgPatch,
    db: DbSession,
    admin: Annotated[Principal, Admin("PLT.org.update")],
) -> OrgMetadataOut:
    meta = await organizations.update_organization(
        db,
        actor_id=admin.user_id,
        org_id=org_id,
        version=body.version,
        name=body.name,
        slug=body.slug,
        timezone=body.timezone,
    )
    return _out(meta)


@router.post("/{org_id}/suspend", response_model=OrgMetadataOut)
async def suspend_organization(
    org_id: uuid.UUID,
    body: SuspendIn,
    db: DbSession,
    admin: Annotated[Principal, Admin("PLT.org.suspend")],
) -> OrgMetadataOut:
    return _out(
        await organizations.suspend_organization(
            db, actor_id=admin.user_id, org_id=org_id, reason=body.reason
        )
    )


@router.post("/{org_id}/activate", response_model=OrgMetadataOut)
async def activate_organization(
    org_id: uuid.UUID, db: DbSession, admin: Annotated[Principal, Admin("PLT.org.activate")]
) -> OrgMetadataOut:
    return _out(
        await organizations.activate_organization(db, actor_id=admin.user_id, org_id=org_id)
    )


@router.put("/{org_id}/limits", response_model=OrgMetadataOut)
async def set_organization_limits(
    org_id: uuid.UUID,
    body: LimitsIn,
    db: DbSession,
    admin: Annotated[Principal, Admin("PLT.org.limits")],
) -> OrgMetadataOut:
    if body.min_interval_seconds not in (None, 60, 120, 300):
        raise AppError(422, "INVALID_INTERVAL", "Minimum interval must be 60, 120 or 300 seconds")
    return _out(
        await organizations.set_limits(
            db, actor_id=admin.user_id, org_id=org_id, values=body.model_dump()
        )
    )


@router.post("/{org_id}/owner-invitations", status_code=status.HTTP_201_CREATED)
async def invite_owner(
    org_id: uuid.UUID,
    body: OwnerInviteIn,
    db: DbSession,
    mailer: AppMailer,
    settings: AppSettings,
    admin: Annotated[Principal, Admin("PLT.org.owner_invite")],
) -> dict[str, str]:
    invitation, token, org_name = await organizations.invite_owner(
        db, actor_id=admin.user_id, org_id=org_id, email=body.email
    )
    await send_invitation_email(
        mailer,
        to=invitation.email_normalized,
        organization=org_name,
        role=invitation.role,
        link=f"{settings.public_base_url}/accept-invite#token={token}",
        inviter="The SentinelOps platform team",
    )
    return {"invitation_id": str(invitation.id), "expires_at": invitation.expires_at.isoformat()}
