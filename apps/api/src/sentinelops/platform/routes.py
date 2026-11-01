"""Platform-plane routes (/api/admin/*) and SYSTEM_ADMIN invitation acceptance.

Every /api/admin route depends on require_platform_admin (PERMISSION_MATRIX.md §2).
"""

import uuid
from dataclasses import asdict
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status

from sentinelops import clock
from sentinelops.db.session import DbSession
from sentinelops.identity.dependencies import (
    AppMailer,
    AppSettings,
    OptionalPrincipal,
    Passwords,
    Principal,
)
from sentinelops.identity.sessions import clear_session_cookies
from sentinelops.mail import OutgoingEmail
from sentinelops.platform import organizations, service
from sentinelops.platform.dependencies import PlatformPermission
from sentinelops.platform.schemas import (
    AcceptInvitationRequest,
    AdminListOut,
    AdminOut,
    AuditOut,
    DailyUsageOut,
    DashboardOut,
    InvitationOut,
    InviteAdminRequest,
    OrgUsageOut,
    QueueHealthOut,
    SettingsOut,
    SettingsUpdate,
    WorkerOut,
)
from sentinelops.platform.usage import platform_usage

router = APIRouter(prefix="/api/admin", tags=["platform"])
public_router = APIRouter(prefix="/api/auth", tags=["auth"])


def _settings_out(row: object) -> SettingsOut:
    return SettingsOut.model_validate(row, from_attributes=True)


@router.get("/dashboard", response_model=DashboardOut)
async def get_dashboard(
    _admin: Annotated[Principal, Depends(PlatformPermission("PLT.dashboard.view"))], db: DbSession
) -> DashboardOut:
    data = await service.dashboard(db)
    usage = await platform_usage(db, clock.now())
    q = usage.queue
    return DashboardOut(
        organizations_by_status=await organizations.org_counts_by_status(db),
        active_admins=data.active_admins,
        pending_invitations=data.pending_invitations,
        recent_audit=[AuditOut(**asdict(row)) for row in data.recent_audit],
        organizations_created_30d=usage.organizations_created_30d,
        monitors_total=sum(o.monitors_live for o in usage.organizations),
        monitors_active=sum(o.monitors_active for o in usage.organizations),
        open_incidents_by_severity={
            "CRITICAL": sum(o.open_incidents_critical for o in usage.organizations),
            "WARNING": sum(o.open_incidents_warning for o in usage.organizations),
        },
        queue=QueueHealthOut(
            checks_per_minute=q.checks_per_minute,
            checks_last_24h=q.checks_last_24h,
            due_backlog=q.due_backlog,
            claim_lag_seconds=q.oldest_due_seconds,
            checks_in_flight=q.checks_in_flight,
            outbox_pending=q.outbox_pending,
            outbox_leased=q.outbox_leased,
            outbox_lag_seconds=q.outbox_oldest_due_seconds,
            outbox_failed_24h=q.outbox_failed_24h,
        ),
        workers=[WorkerOut(**asdict(w)) for w in usage.workers],
        usage_daily=[
            DailyUsageOut(
                day=d.day,
                checks=d.checks,
                failed_checks=d.fail,
                blocked_checks=d.blocked,
                inconclusive_checks=d.inconclusive,
                incidents_opened=d.incidents_opened,
                notifications_sent=d.notifications_sent,
                notification_failures=d.notification_failures,
            )
            for d in usage.daily
        ],
        organizations=[
            OrgUsageOut(
                organization_id=o.organization_id,
                slug=o.slug,
                name=o.name,
                status=o.status,
                active_members=o.active_members,
                monitors_live=o.monitors_live,
                monitors_active=o.monitors_active,
                max_monitors=o.max_monitors,
                status_pages=o.status_pages,
                max_status_pages=o.max_status_pages,
                channels=o.channels,
                max_channels=o.max_channels,
                open_incidents_critical=o.open_incidents_critical,
                open_incidents_warning=o.open_incidents_warning,
            )
            for o in usage.organizations
        ],
    )


@router.get("/platform-admins", response_model=AdminListOut)
async def list_platform_admins(
    _admin: Annotated[Principal, Depends(PlatformPermission("PLT.admin.list"))], db: DbSession
) -> AdminListOut:
    admins, invitations = await service.list_admins(db)
    return AdminListOut(
        admins=[AdminOut(**asdict(a)) for a in admins],
        invitations=[InvitationOut(**asdict(i)) for i in invitations],
    )


@router.post("/platform-admins", response_model=InvitationOut, status_code=status.HTTP_201_CREATED)
async def invite_platform_admin(
    body: InviteAdminRequest,
    admin: Annotated[Principal, Depends(PlatformPermission("PLT.admin.invite"))],
    db: DbSession,
    mailer: AppMailer,
    settings: AppSettings,
) -> InvitationOut:
    invitation, token = await service.invite_admin(db, actor_id=admin.user_id, email=body.email)
    link = f"{settings.public_base_url}/accept-admin-invite#token={token}"
    await mailer.send(
        OutgoingEmail(
            to=invitation.email_normalized,
            subject="You have been invited to administer SentinelOps",
            body=(
                f"{admin.email} invited you to become a SentinelOps platform administrator.\n\n"
                f"Accept within 24 hours: {link}\n\n"
                "If you were not expecting this, ignore this email."
            ),
        )
    )
    return InvitationOut(
        id=invitation.id,
        email=invitation.email_normalized,
        invited_by_email=admin.email,
        created_at=invitation.created_at,
        expires_at=invitation.expires_at,
    )


@router.post(
    "/platform-admins/invitations/{invitation_id}/revoke", status_code=status.HTTP_204_NO_CONTENT
)
async def revoke_platform_admin_invitation(
    invitation_id: uuid.UUID,
    admin: Annotated[Principal, Depends(PlatformPermission("PLT.admin.invite"))],
    db: DbSession,
) -> None:
    await service.revoke_invitation(db, actor_id=admin.user_id, invitation_id=invitation_id)


@router.post("/platform-admins/{user_id}/deactivate", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_platform_admin(
    user_id: uuid.UUID,
    admin: Annotated[Principal, Depends(PlatformPermission("PLT.admin.deactivate"))],
    db: DbSession,
) -> None:
    await service.deactivate_admin(db, actor_id=admin.user_id, target_user_id=user_id)


@router.get("/settings", response_model=SettingsOut)
async def get_platform_settings(
    _admin: Annotated[Principal, Depends(PlatformPermission("PLT.settings.view"))], db: DbSession
) -> SettingsOut:
    return _settings_out(await service.get_settings_row(db))


@router.put("/settings", response_model=SettingsOut)
async def update_platform_settings(
    body: SettingsUpdate,
    admin: Annotated[Principal, Depends(PlatformPermission("PLT.settings.update"))],
    db: DbSession,
) -> SettingsOut:
    values = body.model_dump(exclude={"version"})
    row = await service.update_settings(
        db, actor_id=admin.user_id, version=body.version, values=values
    )
    return _settings_out(row)


@router.get("/audit", response_model=list[AuditOut])
async def list_platform_audit(
    _admin: Annotated[Principal, Depends(PlatformPermission("PLT.audit.view"))],
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before: datetime | None = None,
) -> list[AuditOut]:
    rows = await service.list_audit(db, limit=limit, before=before)
    return [AuditOut(**asdict(row)) for row in rows]


@public_router.post("/platform-invitations/accept", status_code=status.HTTP_204_NO_CONTENT)
async def accept_platform_invitation(
    body: AcceptInvitationRequest,
    response: Response,
    principal: OptionalPrincipal,
    db: DbSession,
    passwords: Passwords,
    settings: AppSettings,
) -> None:
    await service.accept_invitation(
        db,
        passwords,
        token=body.token,
        signed_in_user_id=principal.user_id if principal else None,
        password=body.password,
    )
    # Sessions were revoked on privilege change; the user signs in again.
    clear_session_cookies(response, settings)
