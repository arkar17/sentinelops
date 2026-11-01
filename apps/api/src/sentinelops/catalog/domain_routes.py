"""Domain verification routes under /api/orgs/{org_id}/domains (DOM.view / DOM.manage)."""

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field

from sentinelops.catalog import domains
from sentinelops.catalog.models import VerifiedDomain
from sentinelops.db.session import DbSession
from sentinelops.tenancy.context import OrgContext, OrgPermission

router = APIRouter(prefix="/api/orgs/{org_id}/domains", tags=["domains"])


def Ctx(action: str) -> Any:  # noqa: N802  # reads like a type in signatures
    return Depends(OrgPermission(action))


class DomainIn(BaseModel):
    fqdn: str = Field(min_length=3, max_length=253)


class ExceptionIn(DomainIn):
    reason: str = Field(min_length=10, max_length=500)


class DomainOut(BaseModel):
    id: uuid.UUID
    fqdn: str
    method: str
    status: str
    challenge_expires_at: datetime | None
    verified_at: datetime | None
    expires_at: datetime | None
    last_checked_at: datetime | None
    exception_reason: str | None


class ChallengeOut(BaseModel):
    domain: DomainOut
    record_type: str = "TXT"
    record_name: str
    record_value: str  # shown only now; the server keeps a hash


def _out(domain: VerifiedDomain) -> DomainOut:
    return DomainOut.model_validate(domain, from_attributes=True)


def _challenge(challenge: domains.Challenge) -> ChallengeOut:
    return ChallengeOut(
        domain=_out(challenge.domain),
        record_name=challenge.record_name,
        record_value=challenge.record_value,
    )


@router.get("", response_model=list[DomainOut])
async def list_domains(
    db: DbSession, ctx: Annotated[OrgContext, Ctx("DOM.view")]
) -> list[DomainOut]:
    return [_out(d) for d in await domains.list_domains(db, ctx)]


@router.post("", response_model=ChallengeOut, status_code=status.HTTP_201_CREATED)
async def add_domain(
    body: DomainIn, db: DbSession, ctx: Annotated[OrgContext, Ctx("DOM.manage")]
) -> ChallengeOut:
    return _challenge(await domains.add_domain(db, ctx, body.fqdn))


@router.post("/{domain_id}/challenge", response_model=ChallengeOut)
async def regenerate_challenge(
    domain_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("DOM.manage")]
) -> ChallengeOut:
    return _challenge(await domains.regenerate_challenge(db, ctx, domain_id))


@router.post("/{domain_id}/verify", response_model=DomainOut)
async def verify_domain(
    domain_id: uuid.UUID,
    request: Request,
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("DOM.manage")],
) -> DomainOut:
    lookup: domains.TxtLookup = request.app.state.txt_lookup
    return _out(await domains.verify_domain(db, ctx, domain_id, lookup))


@router.post("/{domain_id}/revoke", response_model=DomainOut)
async def revoke_domain(
    domain_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("DOM.manage")]
) -> DomainOut:
    return _out(await domains.revoke_domain(db, ctx, domain_id))


@router.post("/exception-requests", response_model=DomainOut, status_code=status.HTTP_201_CREATED)
async def request_exception(
    body: ExceptionIn, db: DbSession, ctx: Annotated[OrgContext, Ctx("DOM.manage")]
) -> DomainOut:
    return _out(await domains.request_exception(db, ctx, body.fqdn, body.reason))
