"""Fictional accounts and request helpers for integration tests."""

import uuid

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.models import AuditEvent
from sentinelops.identity.models import AppUser, UserStatus
from sentinelops.identity.passwords import PasswordService
from sentinelops.platform.models import PlatformAdmin, PlatformAdminStatus

PASSWORD = "correct-horse-battery-staple"  # noqa: S105  # fictional test account
NEW_PASSWORD = "another-long-passphrase-42"  # noqa: S105  # fictional test account


async def make_user(
    db: AsyncSession,
    passwords: PasswordService,
    email: str,
    *,
    password: str = PASSWORD,
    platform_admin: bool = False,
    status: str = UserStatus.ACTIVE,
) -> uuid.UUID:
    now = clock.now()
    user = AppUser(
        email=email,
        email_normalized=email.casefold(),
        password_hash=passwords.hash(password) if status != UserStatus.PENDING_ACTIVATION else None,
        status=status,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    await db.flush()
    if platform_admin:
        db.add(PlatformAdmin(user_id=user.id, status=PlatformAdminStatus.ACTIVE, granted_at=now))
    await db.commit()
    return user.id


async def login(client: httpx.AsyncClient, email: str, password: str = PASSWORD) -> httpx.Response:
    return await client.post("/api/auth/login", json={"email": email, "password": password})


def csrf(client: httpx.AsyncClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("sentinelops_csrf") or ""}


async def audit_actions(db: AsyncSession) -> list[str]:
    db.expire_all()
    rows = await db.scalars(select(AuditEvent.action).order_by(AuditEvent.at, AuditEvent.id))
    return list(rows)


def token_from_link(text: str) -> str:
    return text.split("#token=", 1)[1].split()[0]


async def make_org(
    db: AsyncSession,
    *,
    slug: str,
    created_by: uuid.UUID,
    members: dict[uuid.UUID, str],
    name: str | None = None,
) -> uuid.UUID:
    """Fictional organization with ACTIVE members (role by user id)."""
    from sentinelops.tenancy.models import (  # keep G1 helpers import-light
        MemberStatus,
        Organization,
        OrganizationMember,
        OrgStatus,
    )

    now = clock.now()
    org = Organization(
        slug=slug,
        name=name or slug.title(),
        timezone="UTC",
        status=OrgStatus.ACTIVE,
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )
    db.add(org)
    await db.flush()
    for user_id, role in members.items():
        db.add(
            OrganizationMember(
                organization_id=org.id,
                user_id=user_id,
                role=role,
                status=MemberStatus.ACTIVE,
                joined_at=now,
                status_changed_at=now,
            )
        )
    await db.commit()
    return org.id


async def make_verified_domain(
    db: AsyncSession, *, organization_id: uuid.UUID, fqdn: str, created_by: uuid.UUID
) -> uuid.UUID:
    """A DNS-verified domain (fictional) valid for 30 days."""
    from datetime import timedelta

    from sentinelops.catalog.models import (
        DomainMethod,
        DomainStatus,
        VerifiedDomain,
    )

    now = clock.now()
    domain = VerifiedDomain(
        organization_id=organization_id,
        fqdn=fqdn,
        method=DomainMethod.DNS_TXT,
        status=DomainStatus.VERIFIED,
        challenge_token_hash="0" * 64,
        verified_at=now,
        expires_at=now + timedelta(days=30),
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )
    db.add(domain)
    await db.commit()
    return domain.id


async def make_project(
    db: AsyncSession, *, organization_id: uuid.UUID, created_by: uuid.UUID, name: str = "Main"
) -> uuid.UUID:
    from sentinelops.catalog.models import Project
    from sentinelops.db.base import new_id

    now = clock.now()
    project = Project(
        id=new_id(),
        organization_id=organization_id,
        name=name,
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )
    db.add(project)
    await db.commit()
    return project.id


def monitor_body(
    project_id: uuid.UUID,
    url: str = "https://api.acme.example/health?key=s3cr3t-q",
    **extra: object,
) -> dict[str, object]:
    return {"name": "Health", "project_id": str(project_id), "url": url, **extra}
