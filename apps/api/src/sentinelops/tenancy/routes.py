"""Organization routes (/api/orgs/{org_id}), self routes (/api/me), invitation acceptance."""

import uuid
from dataclasses import asdict
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field

from sentinelops.db.session import DbSession
from sentinelops.identity.dependencies import (
    AppMailer,
    AppSettings,
    CurrentPrincipal,
    OptionalPrincipal,
    Passwords,
)
from sentinelops.mail import Mailer, OutgoingEmail
from sentinelops.tenancy import invitations, service
from sentinelops.tenancy.context import OrgContext, OrgPermission

router = APIRouter(prefix="/api/orgs/{org_id}", tags=["organizations"])
self_router = APIRouter(prefix="/api/me", tags=["self"])
invitation_router = APIRouter(prefix="/api/auth/org-invitations", tags=["auth"])

Role = Literal["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER", "VIEWER"]


def Ctx(action: str) -> Any:  # noqa: N802  # reads like a type in signatures
    return Depends(OrgPermission(action))


class LimitsOut(BaseModel):
    max_monitors: int
    min_interval_seconds: int
    max_status_pages: int
    max_channels: int


class OrgOut(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    timezone: str
    status: str
    version: int
    my_role: str
    limits: LimitsOut
    member_count: int
    project_count: int


class OrgUpdate(BaseModel):
    version: int
    name: str | None = Field(default=None, min_length=1, max_length=120)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    role: str
    status: str
    joined_at: datetime


class InviteIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    role: Role


class InvitationOut(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    invited_by_email: str
    created_at: datetime
    expires_at: datetime


class RoleIn(BaseModel):
    role: Role


class StatusIn(BaseModel):
    status: Literal["ACTIVE", "SUSPENDED"]


class OrgAuditOut(BaseModel):
    id: uuid.UUID
    at: datetime
    scope: str
    action: str
    actor_plane: str
    actor_email: str | None
    entity_kind: str | None
    entity_id: uuid.UUID | None
    details: dict[str, Any]


def _org_out(profile: service.OrgProfile) -> OrgOut:
    data = asdict(profile)
    return OrgOut(**data)


async def send_invitation_email(
    mailer: Mailer, *, to: str, organization: str, role: str, link: str, inviter: str
) -> None:
    await mailer.send(
        OutgoingEmail(
            to=to,
            subject=f"You have been invited to {organization} on SentinelOps",
            body=(
                f"{inviter} invited you to join {organization} as {role}.\n\n"
                f"Accept within 7 days: {link}\n\n"
                "If you were not expecting this, ignore this email."
            ),
        )
    )


@router.get("", response_model=OrgOut)
async def get_organization(db: DbSession, ctx: Annotated[OrgContext, Ctx("ORG.view")]) -> OrgOut:
    return _org_out(await service.get_profile(db, ctx))


@router.patch("", response_model=OrgOut)
async def update_organization(
    body: OrgUpdate, db: DbSession, ctx: Annotated[OrgContext, Ctx("ORG.update")]
) -> OrgOut:
    profile = await service.update_profile(
        db, ctx, version=body.version, name=body.name, timezone=body.timezone
    )
    return _org_out(profile)


@router.get("/members", response_model=list[MemberOut])
async def list_members(
    db: DbSession, ctx: Annotated[OrgContext, Ctx("MEM.list")]
) -> list[MemberOut]:
    return [MemberOut(**asdict(m)) for m in await service.list_members(db, ctx)]


@router.get("/invitations", response_model=list[InvitationOut])
async def list_invitations(
    db: DbSession, ctx: Annotated[OrgContext, Ctx("MEM.invite")]
) -> list[InvitationOut]:
    return [InvitationOut(**asdict(i)) for i in await service.list_invitations(db, ctx)]


@router.post("/invitations", response_model=InvitationOut, status_code=status.HTTP_201_CREATED)
async def invite_member(
    body: InviteIn,
    db: DbSession,
    mailer: AppMailer,
    settings: AppSettings,
    ctx: Annotated[OrgContext, Ctx("MEM.invite")],
) -> InvitationOut:
    invitation, token = await service.invite_member(db, ctx, email=body.email, role=body.role)
    await send_invitation_email(
        mailer,
        to=invitation.email_normalized,
        organization=ctx.name,
        role=invitation.role,
        link=f"{settings.public_base_url}/accept-invite#token={token}",
        inviter=ctx.principal.email,
    )
    return InvitationOut(
        id=invitation.id,
        email=invitation.email_normalized,
        role=invitation.role,
        invited_by_email=ctx.principal.email,
        created_at=invitation.created_at,
        expires_at=invitation.expires_at,
    )


@router.delete("/invitations/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_invitation(
    invitation_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("MEM.invitation.revoke")],
) -> None:
    await service.revoke_invitation(db, ctx, invitation_id)


@router.put("/members/{user_id}/role", status_code=status.HTTP_204_NO_CONTENT)
async def change_member_role(
    user_id: uuid.UUID,
    body: RoleIn,
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("MEM.role.change")],
) -> None:
    await service.change_role(db, ctx, user_id=user_id, role=body.role)


@router.put("/members/{user_id}/status", status_code=status.HTTP_204_NO_CONTENT)
async def change_member_status(
    user_id: uuid.UUID,
    body: StatusIn,
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("MEM.status.change")],
) -> None:
    await service.change_status(db, ctx, user_id=user_id, status=body.status)


@router.delete("/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    user_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("MEM.remove")]
) -> None:
    await service.remove_member(db, ctx, user_id=user_id)


@router.post("/leave", status_code=status.HTTP_204_NO_CONTENT)
async def leave_organization(db: DbSession, ctx: Annotated[OrgContext, Ctx("MEM.leave")]) -> None:
    await service.leave(db, ctx)


@router.get("/audit", response_model=list[OrgAuditOut])
async def organization_audit(
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("ORG.audit.view")],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before: datetime | None = None,
) -> list[OrgAuditOut]:
    rows = await service.list_audit(db, ctx, limit=limit, before=before)
    return [OrgAuditOut(**asdict(r)) for r in rows]


# --- self ----------------------------------------------------------------------------------------


class MembershipOut(BaseModel):
    organization_id: uuid.UUID
    slug: str
    name: str
    organization_status: str
    role: str


class MyOrganizationsOut(BaseModel):
    organizations: list[MembershipOut]
    selected_org_id: uuid.UUID | None


class PreferencesIn(BaseModel):
    selected_org_id: uuid.UUID | None


@self_router.get("/organizations", response_model=MyOrganizationsOut)
async def my_organizations(principal: CurrentPrincipal, db: DbSession) -> MyOrganizationsOut:
    memberships, selected = await service.my_organizations(db, principal.user_id)
    return MyOrganizationsOut(
        organizations=[MembershipOut(**asdict(m)) for m in memberships], selected_org_id=selected
    )


@self_router.put("/preferences", status_code=status.HTTP_204_NO_CONTENT)
async def set_preferences(body: PreferencesIn, principal: CurrentPrincipal, db: DbSession) -> None:
    await service.select_organization(db, principal.user_id, body.selected_org_id)


# --- invitation acceptance (token in body, never in the URL) -------------------------------------


class TokenIn(BaseModel):
    token: str = Field(min_length=16, max_length=128)


class AcceptIn(TokenIn):
    password: str | None = Field(default=None, min_length=1, max_length=128)


class PreviewOut(BaseModel):
    organization_name: str
    role: str
    email: str
    account_exists: bool


class AcceptOut(BaseModel):
    organization_id: uuid.UUID


@invitation_router.post("/preview", response_model=PreviewOut)
async def preview_invitation(body: TokenIn, db: DbSession) -> PreviewOut:
    return PreviewOut(**asdict(await invitations.preview_invitation(db, body.token)))


@invitation_router.post("/accept", response_model=AcceptOut)
async def accept_invitation(
    body: AcceptIn, principal: OptionalPrincipal, db: DbSession, passwords: Passwords
) -> AcceptOut:
    organization_id = await invitations.accept_invitation(
        db,
        passwords,
        token=body.token,
        signed_in_user_id=principal.user_id if principal else None,
        password=body.password,
    )
    return AcceptOut(organization_id=organization_id)
