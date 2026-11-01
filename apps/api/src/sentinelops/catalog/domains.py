"""Domain ownership verification by DNS TXT (OD-05, FR-MON-003) and exception requests.

Record: ``_sentinelops-challenge.<fqdn>`` TXT ``sentinelops-domain-verification=<token>``.
Each organization gets its own random token per domain and only its hash is stored, so one
organization's proof can never satisfy another organization's challenge.
"""

import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

import dns.asyncresolver
import dns.exception
import dns.resolver
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.catalog.eligibility import activate_covered_monitors
from sentinelops.catalog.models import DomainMethod, DomainStatus, VerifiedDomain
from sentinelops.errors import AppError
from sentinelops.identity.tokens import hash_token, new_token
from sentinelops.probe_policy.urls import UrlPolicyError, normalize_hostname
from sentinelops.tenancy.context import OrgContext

CHALLENGE_PREFIX = "_sentinelops-challenge"
TXT_VALUE_PREFIX = "sentinelops-domain-verification="
CHALLENGE_TTL = timedelta(days=7)  # IC-06
VERIFICATION_VALIDITY = timedelta(days=30)  # FR-MON-003
RENEWAL_WINDOW = timedelta(days=3)

TxtLookup = Callable[[str], Awaitable[Sequence[str]]]


class DnsLookupError(Exception):
    """Transient DNS failure (timeout, SERVFAIL)."""


async def dns_txt_lookup(name: str) -> Sequence[str]:
    """TXT strings for ``name``; empty when the name or record does not exist."""
    resolver = dns.asyncresolver.Resolver()
    try:
        answer = await resolver.resolve(name, "TXT", lifetime=5.0)
    except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer:
        return []
    except dns.exception.DNSException as exc:
        raise DnsLookupError from exc
    return [b"".join(rdata.strings).decode(errors="replace") for rdata in answer]  # pyright: ignore[reportAttributeAccessIssue, reportUnknownArgumentType, reportUnknownMemberType]


def challenge_name(fqdn: str) -> str:
    return f"{CHALLENGE_PREFIX}.{fqdn}"


def txt_matches(values: Sequence[str], token_hash: str | None) -> bool:
    if token_hash is None:
        return False
    for value in values:
        stripped = value.strip()
        if (
            stripped.startswith(TXT_VALUE_PREFIX)
            and hash_token(stripped.removeprefix(TXT_VALUE_PREFIX)) == token_hash
        ):
            return True
    return False


def normalize_fqdn(raw: str) -> str:
    try:
        return normalize_hostname(raw)
    except UrlPolicyError as exc:
        raise AppError(422, "INVALID_DOMAIN", exc.message) from exc


def _audit(
    db: AsyncSession, ctx: OrgContext, action: str, domain_id: uuid.UUID, **details: object
) -> None:
    record(
        db,
        action,
        scope="ORGANIZATION",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        actor_plane="ORG",
        entity_kind="verified_domain",
        entity_id=domain_id,
        details=dict(details) or None,
    )


@dataclass(frozen=True)
class Challenge:
    domain: VerifiedDomain
    record_name: str
    record_value: str


async def list_domains(db: AsyncSession, ctx: OrgContext) -> list[VerifiedDomain]:
    return list(
        await db.scalars(
            select(VerifiedDomain)
            .where(VerifiedDomain.organization_id == ctx.organization_id)
            .order_by(VerifiedDomain.fqdn)
        )
    )


async def _get(db: AsyncSession, ctx: OrgContext, domain_id: uuid.UUID) -> VerifiedDomain:
    domain = await db.scalar(
        select(VerifiedDomain)
        .where(
            VerifiedDomain.organization_id == ctx.organization_id, VerifiedDomain.id == domain_id
        )
        .with_for_update()
    )
    if domain is None:
        raise AppError(404, "NOT_FOUND", "Domain not found")
    return domain


def _issue_challenge(domain: VerifiedDomain, now: datetime) -> Challenge:
    token = new_token()
    domain.method = DomainMethod.DNS_TXT
    domain.status = DomainStatus.PENDING
    domain.challenge_token_hash = hash_token(token)
    domain.challenge_expires_at = now + CHALLENGE_TTL
    domain.verified_at = None
    domain.expires_at = None
    domain.exception_reason = None
    domain.decided_by = None
    return Challenge(domain, challenge_name(domain.fqdn), f"{TXT_VALUE_PREFIX}{token}")


async def add_domain(db: AsyncSession, ctx: OrgContext, fqdn: str) -> Challenge:
    fqdn = normalize_fqdn(fqdn)
    now = clock.now()
    domain = await db.scalar(
        select(VerifiedDomain)
        .where(VerifiedDomain.organization_id == ctx.organization_id, VerifiedDomain.fqdn == fqdn)
        .with_for_update()
    )
    if domain is not None and domain.status in (DomainStatus.PENDING, DomainStatus.VERIFIED):
        raise AppError(
            409, "DOMAIN_EXISTS", "This domain is already added; regenerate its challenge"
        )
    if domain is None:
        domain = VerifiedDomain(
            organization_id=ctx.organization_id,
            fqdn=fqdn,
            created_by=ctx.user_id,
            created_at=now,
            updated_at=now,
        )
        db.add(domain)
    else:
        domain.version += 1
    challenge = _issue_challenge(domain, now)
    await db.flush()
    _audit(db, ctx, AuditAction.DOMAIN_ADDED, domain.id, fqdn=fqdn)
    await db.commit()
    return challenge


async def regenerate_challenge(
    db: AsyncSession, ctx: OrgContext, domain_id: uuid.UUID
) -> Challenge:
    domain = await _get(db, ctx, domain_id)
    if domain.status == DomainStatus.VERIFIED and domain.method == DomainMethod.DNS_TXT:
        raise AppError(
            409, "ALREADY_VERIFIED", "The domain is verified; revoke it first to re-issue"
        )
    challenge = _issue_challenge(domain, clock.now())
    domain.version += 1
    _audit(db, ctx, AuditAction.DOMAIN_CHALLENGE_REGENERATED, domain.id)
    await db.commit()
    return challenge


async def verify_domain(
    db: AsyncSession, ctx: OrgContext, domain_id: uuid.UUID, lookup: TxtLookup
) -> VerifiedDomain:
    domain = await _get(db, ctx, domain_id)
    now = clock.now()
    if domain.method != DomainMethod.DNS_TXT or domain.status not in (
        DomainStatus.PENDING,
        DomainStatus.EXPIRED,
    ):
        raise AppError(409, "NOT_PENDING", "This domain has no pending DNS challenge")
    if domain.challenge_expires_at is None or domain.challenge_expires_at <= now:
        raise AppError(410, "CHALLENGE_EXPIRED", "The challenge expired; regenerate it")
    try:
        values = await lookup(challenge_name(domain.fqdn))
    except DnsLookupError as exc:
        raise AppError(503, "DNS_UNAVAILABLE", "DNS lookup failed; try again shortly") from exc
    domain.last_checked_at = now
    if not txt_matches(values, domain.challenge_token_hash):
        await db.commit()
        raise AppError(422, "VERIFICATION_FAILED", "The TXT record was not found or does not match")
    domain.status = DomainStatus.VERIFIED
    domain.verified_at = now
    domain.expires_at = now + VERIFICATION_VALIDITY
    domain.version += 1
    activated = await activate_covered_monitors(db, ctx.organization_id)
    _audit(db, ctx, AuditAction.DOMAIN_VERIFIED, domain.id, activated_monitors=activated)
    await db.commit()
    return domain


async def revoke_domain(db: AsyncSession, ctx: OrgContext, domain_id: uuid.UUID) -> VerifiedDomain:
    domain = await _get(db, ctx, domain_id)
    domain.status = DomainStatus.REVOKED
    domain.challenge_token_hash = None
    domain.challenge_expires_at = None
    domain.expires_at = None
    domain.version += 1
    _audit(db, ctx, AuditAction.DOMAIN_REVOKED, domain.id)
    await db.commit()
    return domain


async def request_exception(
    db: AsyncSession, ctx: OrgContext, fqdn: str, reason: str
) -> VerifiedDomain:
    """Ask a SYSTEM_ADMIN to allow a hostname without DNS proof (FR-PLT-009)."""
    fqdn = normalize_fqdn(fqdn)
    now = clock.now()
    domain = await db.scalar(
        select(VerifiedDomain)
        .where(VerifiedDomain.organization_id == ctx.organization_id, VerifiedDomain.fqdn == fqdn)
        .with_for_update()
    )
    if domain is not None and domain.status == DomainStatus.VERIFIED:
        raise AppError(409, "ALREADY_VERIFIED", "This domain is already verified")
    if domain is None:
        domain = VerifiedDomain(
            organization_id=ctx.organization_id,
            fqdn=fqdn,
            created_by=ctx.user_id,
            created_at=now,
            updated_at=now,
        )
        db.add(domain)
    else:
        domain.version += 1
    domain.method = DomainMethod.ADMIN_EXCEPTION
    domain.status = DomainStatus.PENDING
    domain.challenge_token_hash = None
    domain.challenge_expires_at = None
    domain.exception_reason = reason
    domain.decided_by = None
    await db.flush()
    _audit(db, ctx, AuditAction.DOMAIN_EXCEPTION_REQUESTED, domain.id, fqdn=fqdn)
    await db.commit()
    return domain


async def renew_and_expire(db: AsyncSession, lookup: TxtLookup) -> tuple[int, int]:
    """Worker task: re-verify DNS proofs nearing expiry; expire lapsed ones. Returns counts."""
    now = clock.now()
    renewed = expired = 0
    due = list(
        await db.scalars(
            select(VerifiedDomain)
            .where(
                VerifiedDomain.status == DomainStatus.VERIFIED,
                VerifiedDomain.expires_at <= now + RENEWAL_WINDOW,
            )
            .with_for_update(skip_locked=True)
        )
    )
    for domain in due:
        if domain.method == DomainMethod.DNS_TXT:
            try:
                values = await lookup(challenge_name(domain.fqdn))
            except DnsLookupError:
                values = None
            domain.last_checked_at = now
            if values is not None and txt_matches(values, domain.challenge_token_hash):
                domain.verified_at = now
                domain.expires_at = now + VERIFICATION_VALIDITY
                renewed += 1
                continue
        if domain.expires_at is not None and domain.expires_at <= now:
            domain.status = DomainStatus.EXPIRED
            expired += 1
    await db.commit()
    return renewed, expired
