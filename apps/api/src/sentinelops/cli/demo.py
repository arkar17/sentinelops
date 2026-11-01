"""Fictional two-organization demo data (04_IMPLEMENTATION_PLAN_CLAUDE_PRO.md G7).

Opt-in only: ``sentinelops seed-demo --confirm`` refuses unless the target database is named
``*_demo`` (or the disposable ``sentinelops_test``) and contains no accounts yet. Every name,
address and domain is fictional (``.example`` / ``.test``). Passwords are generated per run,
stored only as Argon2id hashes and printed once to the operator's terminal.

Demo monitors are ACTIVE but scheduled far in the future, so a worker never probes the fictional
hosts; measurements, incidents and notification history are synthetic rows.
"""

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.catalog.models import (
    DomainMethod,
    DomainStatus,
    Monitor,
    MonitorLifecycle,
    Project,
    VerifiedDomain,
)
from sentinelops.config import Settings
from sentinelops.db.base import new_id
from sentinelops.errors import AppError
from sentinelops.identity.models import AppUser, UserStatus
from sentinelops.identity.passwords import PasswordService
from sentinelops.incidents.events import emit
from sentinelops.incidents.models import (
    EventType,
    Incident,
    IncidentStatus,
    IncidentType,
    Resolution,
    Severity,
)
from sentinelops.measurements.models import Measurement
from sentinelops.measurements.rollups import hour_floor, rollup_range
from sentinelops.notifications.models import (
    NotificationChannel,
    NotificationChannelRecipient,
    NotificationDelivery,
    NotificationOutbox,
    NotificationRoute,
    NotifyEvent,
    OutboxState,
)
from sentinelops.platform.models import PlatformAdmin, PlatformAdminStatus
from sentinelops.scheduler.models import MonitorHealth, MonitorSchedule
from sentinelops.secrets.cipher import SecretBinding, SecretBox
from sentinelops.status_pages.models import StatusPage, StatusPageMonitor
from sentinelops.status_pages.service import refresh_snapshot
from sentinelops.tenancy.models import (
    MemberStatus,
    Organization,
    OrganizationMember,
    OrgRole,
    OrgStatus,
)

ALLOWED_SUFFIXES = ("_demo",)
ALLOWED_EXACT = ("sentinelops_test",)
FAR_FUTURE = timedelta(days=3650)


class DemoRefusedError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(409, "DEMO_REFUSED", message)


def check_database_name(name: str | None) -> None:
    if not name or not (name.endswith(ALLOWED_SUFFIXES) or name in ALLOWED_EXACT):
        raise DemoRefusedError("Demo data may only be written to a database named *_demo")


@dataclass
class DemoAccounts:
    credentials: list[tuple[str, str, str]] = field(default_factory=list[tuple[str, str, str]])

    def add(self, email: str, role: str, password: str) -> None:
        self.credentials.append((email, role, password))


async def _user(
    db: AsyncSession,
    passwords: PasswordService,
    accounts: DemoAccounts,
    email: str,
    role: str,
    now: datetime,
) -> uuid.UUID:
    password = secrets.token_urlsafe(18)
    user = AppUser(
        id=new_id(),
        email=email,
        email_normalized=email.casefold(),
        password_hash=passwords.hash(password),
        status=UserStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    accounts.add(email, role, password)
    return user.id


async def _org(
    db: AsyncSession,
    *,
    slug: str,
    name: str,
    timezone: str,
    owner: uuid.UUID,
    members: dict[uuid.UUID, str],
    now: datetime,
) -> uuid.UUID:
    org = Organization(
        id=new_id(),
        slug=slug,
        name=name,
        timezone=timezone,
        status=OrgStatus.ACTIVE,
        created_by=owner,
        created_at=now - timedelta(days=40),
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
                joined_at=now - timedelta(days=39),
                status_changed_at=now,
            )
        )
    return org.id


async def _monitor(
    db: AsyncSession,
    box: SecretBox,
    *,
    org: uuid.UUID,
    project: uuid.UUID,
    owner: uuid.UUID,
    name: str,
    host: str,
    health: str,
    now: datetime,
) -> Monitor:
    monitor = Monitor(
        id=new_id(),
        organization_id=org,
        project_id=project,
        kind="HTTP",
        name=name,
        hostname=host,
        display_url=f"https://{host}/health",
        method="GET",
        interval_seconds=60,
        timeout_ms=10000,
        retry_attempts=1,
        expected_status_json=[[200, 299]],
        header_count=0,
        latency_threshold_ms=800,
        failure_threshold=3,
        recovery_threshold=2,
        tls_warn_days=14,
        tags_json=["demo"],
        lifecycle=MonitorLifecycle.ACTIVE,
        created_by=owner,
        created_at=now - timedelta(days=35),
        updated_at=now,
    )
    sealed = box.seal(f"https://{host}/health", SecretBinding(org, "monitor", monitor.id, "url"))
    monitor.url_ciphertext, monitor.url_key_id = sealed.ciphertext, sealed.key_id
    db.add(monitor)
    await db.flush()
    db.add(
        MonitorSchedule(
            monitor_id=monitor.id,
            organization_id=org,
            next_due_at=now + FAR_FUTURE,  # never probed by a worker
            generation=1,
            missed_slots=0,
        )
    )
    db.add(
        MonitorHealth(
            monitor_id=monitor.id,
            organization_id=org,
            state=health,
            last_conclusive_at=now - timedelta(minutes=1),
            last_change_at=now - timedelta(hours=1),
        )
    )
    return monitor


def _measurements(monitor: Monitor, now: datetime, failing_from: int | None) -> list[Measurement]:
    """24 hours of one-minute checks; optional failures over the last ``failing_from`` minutes."""
    rows: list[Measurement] = []
    for minute in range(24 * 60, 0, -1):
        at = now - timedelta(minutes=minute)
        failing = failing_from is not None and minute <= failing_from
        slow = minute % 97 == 0
        result = "FAIL" if failing else ("SLOW" if slow else "PASS")
        rows.append(
            Measurement(
                id=new_id(),
                organization_id=monitor.organization_id,
                monitor_id=monitor.id,
                job_id=new_id(),
                trigger="SCHEDULED",
                source_kind="HTTP_PROBE",
                schema_version=1,
                scheduled_for=at,
                observed_at=at,
                ingested_at=at,
                result=result,
                failure_category="HTTP_STATUS_MISMATCH" if failing else None,
                http_status=503 if failing else 200,
                elapsed_ms=None if failing else (950 if slow else 120 + (minute * 7) % 90),
                attempt_count=1,
                tls_not_after=now + timedelta(days=9 if monitor.name == "Storefront" else 80),
            )
        )
    return rows


async def _incident(
    db: AsyncSession,
    monitor: Monitor,
    *,
    kind: str,
    opened_at: datetime,
    resolved_at: datetime | None,
) -> Incident:
    incident = Incident(
        id=new_id(),
        organization_id=monitor.organization_id,
        monitor_id=monitor.id,
        type=kind,
        source_kind="HTTP_PROBE",
        severity=Severity.CRITICAL if kind == IncidentType.OUTAGE else Severity.WARNING,
        status=IncidentStatus.OPEN,
        title_sanitized="Outage detected"
        if kind == IncidentType.OUTAGE
        else "TLS certificate expiring",
        opened_at=opened_at,
        last_event_at=opened_at,
        version=1,
    )
    db.add(incident)
    await db.flush()
    await emit(db, incident, EventType.OPENED, at=opened_at, details={"demo": True})
    if resolved_at is not None:
        incident.status = IncidentStatus.RESOLVED
        incident.resolved_at = resolved_at
        incident.resolution = Resolution.AUTO
        incident.version += 1
        await emit(db, incident, EventType.RESOLVED, at=resolved_at, details={"demo": True})
    return incident


async def seed_demo(
    db: AsyncSession, settings: Settings, passwords: PasswordService, box: SecretBox
) -> DemoAccounts:
    check_database_name(await db.scalar(text("SELECT current_database()")))
    if await db.scalar(select(func.count()).select_from(AppUser)):
        raise DemoRefusedError("The database already has accounts; demo data needs an empty one")
    now = clock.now()
    accounts = DemoAccounts()
    root = await _user(
        db, passwords, accounts, "platform-admin@sentinelops.test", "SYSTEM_ADMIN", now
    )
    await db.flush()
    db.add(PlatformAdmin(user_id=root, status=PlatformAdminStatus.ACTIVE, granted_at=now))

    people: dict[str, tuple[uuid.UUID, str]] = {}
    for email, role in (
        ("olivia.owner@northwind.test", OrgRole.OWNER),
        ("adam.admin@northwind.test", OrgRole.ADMIN),
        ("maria.member@northwind.test", OrgRole.MEMBER),
        ("victor.viewer@northwind.test", OrgRole.VIEWER),
        ("chris.owner@contoso.test", OrgRole.OWNER),
        ("mia.member@contoso.test", OrgRole.MEMBER),
    ):
        people[email] = (await _user(db, passwords, accounts, email, role, now), role)
    await db.flush()
    northwind_members = {uid: role for email, (uid, role) in people.items() if "northwind" in email}
    contoso_members = {uid: role for email, (uid, role) in people.items() if "contoso" in email}
    olivia = people["olivia.owner@northwind.test"][0]
    chris = people["chris.owner@contoso.test"][0]
    northwind = await _org(
        db,
        slug="northwind",
        name="Northwind Traders (demo)",
        timezone="Europe/Berlin",
        owner=olivia,
        members=northwind_members,
        now=now,
    )
    contoso = await _org(
        db,
        slug="contoso",
        name="Contoso Health (demo)",
        timezone="America/New_York",
        owner=chris,
        members=contoso_members,
        now=now,
    )

    monitors: dict[str, Monitor] = {}
    for org, owner, fqdn, project_name, specs in (
        (
            northwind,
            olivia,
            "northwind.example",
            "Customer platform",
            [
                ("Storefront", "shop.northwind.example", "UP"),
                ("Payments API", "pay.northwind.example", "DOWN"),
            ],
        ),
        (
            contoso,
            chris,
            "contoso.example",
            "Patient portal",
            [("Portal API", "api.contoso.example", "UP")],
        ),
    ):
        db.add(
            VerifiedDomain(
                id=new_id(),
                organization_id=org,
                fqdn=fqdn,
                method=DomainMethod.DNS_TXT,
                status=DomainStatus.VERIFIED,
                challenge_token_hash="0" * 64,
                verified_at=now - timedelta(days=36),
                expires_at=now + timedelta(days=24),
                created_by=owner,
                created_at=now - timedelta(days=36),
                updated_at=now,
            )
        )
        project = Project(
            id=new_id(),
            organization_id=org,
            name=project_name,
            created_by=owner,
            created_at=now - timedelta(days=36),
            updated_at=now,
        )
        db.add(project)
        await db.flush()
        for name, host, health in specs:
            monitors[name] = await _monitor(
                db,
                box,
                org=org,
                project=project.id,
                owner=owner,
                name=name,
                host=host,
                health=health,
                now=now,
            )

    # Email alerts for Northwind, so incidents leave notification history.
    channel = NotificationChannel(
        id=new_id(),
        organization_id=northwind,
        type="EMAIL",
        label="On-call team",
        enabled=True,
        created_by=olivia,
        created_at=now,
        updated_at=now,
        version=1,
    )
    db.add(channel)
    await db.flush()
    for email in ("olivia.owner@northwind.test", "adam.admin@northwind.test"):
        db.add(
            NotificationChannelRecipient(
                organization_id=northwind, channel_id=channel.id, user_id=people[email][0]
            )
        )
    db.add(
        NotificationRoute(
            organization_id=northwind,
            channel_id=channel.id,
            event_types_json=list(NotifyEvent.ROUTABLE),
            enabled=True,
            created_at=now,
        )
    )
    await db.flush()

    for row in _measurements(monitors["Storefront"], now, None):
        db.add(row)
    for row in _measurements(monitors["Payments API"], now, failing_from=25):
        db.add(row)
    for row in _measurements(monitors["Portal API"], now, None):
        db.add(row)
    await db.flush()

    await _incident(
        db,
        monitors["Payments API"],
        kind=IncidentType.OUTAGE,
        opened_at=now - timedelta(hours=6, minutes=3),
        resolved_at=now - timedelta(hours=5, minutes=41),
    )
    await _incident(
        db,
        monitors["Payments API"],
        kind=IncidentType.OUTAGE,
        opened_at=now - timedelta(minutes=23),
        resolved_at=None,
    )
    await _incident(
        db,
        monitors["Storefront"],
        kind=IncidentType.TLS_EXPIRY,
        opened_at=now - timedelta(hours=2),
        resolved_at=None,
    )
    await _incident(
        db,
        monitors["Portal API"],
        kind=IncidentType.OUTAGE,
        opened_at=now - timedelta(days=2),
        resolved_at=now - timedelta(days=2) + timedelta(minutes=4),
    )
    await db.flush()

    # Synthetic delivery history: everything queued above was "sent" through the relay.
    for item in await db.scalars(
        select(NotificationOutbox).where(NotificationOutbox.organization_id == northwind)
    ):
        item.state = OutboxState.SENT
        item.attempts = 1
        item.last_result_code = "SENT"
        item.sent_at = item.created_at + timedelta(seconds=4)
        for recipient in ("olivia.owner@northwind.test", "adam.admin@northwind.test"):
            db.add(
                NotificationDelivery(
                    organization_id=northwind,
                    outbox_id=item.id,
                    attempt=1,
                    recipient_user_id=people[recipient][0],
                    result_code="SENT",
                    attempted_at=item.sent_at,
                )
            )

    page = StatusPage(
        id=new_id(),
        organization_id=northwind,
        public_slug="northwind-status",
        title="Northwind Traders status",
        enabled=True,
        created_by=olivia,
        created_at=now,
        updated_at=now,
        version=1,
    )
    db.add(page)
    await db.flush()
    for order, (name, public) in enumerate(
        (("Storefront", "Online shop"), ("Payments API", "Payments"))
    ):
        db.add(
            StatusPageMonitor(
                organization_id=northwind,
                status_page_id=page.id,
                monitor_id=monitors[name].id,
                public_display_name=public,
                sort_order=order,
            )
        )
    await db.flush()
    await rollup_range(db, hour_floor(now - timedelta(days=2)), hour_floor(now))
    await refresh_snapshot(db, page, now)
    await db.commit()
    return accounts
