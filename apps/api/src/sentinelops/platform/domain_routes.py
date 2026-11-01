"""SYSTEM_ADMIN decisions on domain-verification exceptions (FR-PLT-009).

An approved exception lets an organization monitor a hostname without DNS proof. It never relaxes
the SSRF destination policy: blocked addresses stay blocked.
"""

import uuid
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.catalog.eligibility import activate_covered_monitors
from sentinelops.catalog.models import DomainMethod, DomainStatus, VerifiedDomain
from sentinelops.db.session import DbSession
from sentinelops.errors import AppError
from sentinelops.identity.dependencies import Principal
from sentinelops.platform.dependencies import PlatformPermission
from sentinelops.tenancy.models import Organization

router = APIRouter(prefix="/api/admin/domain-exceptions", tags=["platform"])
Decide = Annotated[Principal, Depends(PlatformPermission("PLT.domain_exception.decide"))]
DEFAULT_EXCEPTION_DAYS = 90  # IC-07


class ExceptionRequestOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    organization_slug: str
    organization_name: str
    fqdn: str
    reason: str | None
    requested_at: datetime


class ApproveIn(BaseModel):
    days: int = Field(default=DEFAULT_EXCEPTION_DAYS, ge=1, le=365)


async def _pending(db: DbSession, exception_id: uuid.UUID) -> VerifiedDomain:
    domain = await db.scalar(
        select(VerifiedDomain)
        .where(
            VerifiedDomain.id == exception_id,
            VerifiedDomain.method == DomainMethod.ADMIN_EXCEPTION,
            VerifiedDomain.status == DomainStatus.PENDING,
        )
        .with_for_update()
    )
    if domain is None:
        raise AppError(404, "NOT_FOUND", "Pending exception request not found")
    return domain


def _audit(
    db: DbSession, admin: Principal, action: str, domain: VerifiedDomain, **details: object
) -> None:
    record(
        db,
        action,
        scope="PLATFORM",
        organization_id=domain.organization_id,
        actor_user_id=admin.user_id,
        actor_plane="PLATFORM",
        entity_kind="verified_domain",
        entity_id=domain.id,
        details={"fqdn": domain.fqdn, **details},
    )


@router.get("", response_model=list[ExceptionRequestOut])
async def list_pending(db: DbSession, _admin: Decide) -> list[ExceptionRequestOut]:
    rows = await db.execute(
        select(VerifiedDomain, Organization)
        .join(Organization, Organization.id == VerifiedDomain.organization_id)
        .where(
            VerifiedDomain.method == DomainMethod.ADMIN_EXCEPTION,
            VerifiedDomain.status == DomainStatus.PENDING,
        )
        .order_by(VerifiedDomain.updated_at)
    )
    return [
        ExceptionRequestOut(
            id=d.id,
            organization_id=o.id,
            organization_slug=o.slug,
            organization_name=o.name,
            fqdn=d.fqdn,
            reason=d.exception_reason,
            requested_at=d.updated_at,
        )
        for d, o in rows
    ]


@router.post("/{exception_id}/approve", status_code=status.HTTP_204_NO_CONTENT)
async def approve(exception_id: uuid.UUID, body: ApproveIn, db: DbSession, admin: Decide) -> None:
    domain = await _pending(db, exception_id)
    now = clock.now()
    domain.status = DomainStatus.VERIFIED
    domain.verified_at = now
    domain.expires_at = now + timedelta(days=body.days)
    domain.decided_by = admin.user_id
    domain.version += 1
    activated = await activate_covered_monitors(db, domain.organization_id)
    _audit(
        db,
        admin,
        AuditAction.DOMAIN_EXCEPTION_APPROVED,
        domain,
        days=body.days,
        activated_monitors=activated,
    )
    await db.commit()


@router.post("/{exception_id}/reject", status_code=status.HTTP_204_NO_CONTENT)
async def reject(exception_id: uuid.UUID, db: DbSession, admin: Decide) -> None:
    domain = await _pending(db, exception_id)
    domain.status = DomainStatus.REJECTED
    domain.decided_by = admin.user_id
    domain.version += 1
    _audit(db, admin, AuditAction.DOMAIN_EXCEPTION_REJECTED, domain)
    await db.commit()
