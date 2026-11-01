"""Shared G5 fixtures: a fictional tenant with one monitor, fake Telegram and mail transports,
and helpers that push mocked check results through the real claim/complete path."""

import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.mail import MailDeliveryError, OutgoingEmail
from sentinelops.notifications.dispatcher import Dispatcher
from sentinelops.notifications.models import NotificationOutbox
from sentinelops.notifications.telegram import SendResult
from sentinelops.probes.http.engine import CheckOutcome
from sentinelops.scheduler.models import MonitorSchedule
from sentinelops.scheduler.service import Capacity, claim_jobs, complete_job
from sentinelops.tenancy.models import OrgRole
from tests.integration.conftest import ClientFactory, FrozenClock
from tests.integration.helpers import (
    csrf,
    login,
    make_org,
    make_project,
    make_user,
    make_verified_domain,
    monitor_body,
)

SECRET_QUERY = "s3cr3t-q"  # noqa: S105  # fictional query-string value
BOT_TOKEN = "123456789:AAFakeTokenForTestsOnly_abcdefghijkl"  # noqa: S105  # fictional
CHAT_ID = "-1001234567890"


@dataclass
class FakeTelegram:
    """Records messages; ``script`` yields results in order, then SENT."""

    script: list[SendResult] = field(default_factory=list[SendResult])
    sent: list[tuple[str, str, str]] = field(default_factory=list[tuple[str, str, str]])

    async def send_message(self, bot_token: str, chat_id: str, text: str) -> SendResult:
        self.sent.append((bot_token, chat_id, text))
        if self.script:
            return self.script.pop(0)
        return SendResult("SENT", ok=True, provider_ref=str(len(self.sent)))


@dataclass
class FakeMailer:
    """``failures`` maps a recipient to errors raised on successive sends."""

    sent: list[OutgoingEmail] = field(default_factory=list[OutgoingEmail])
    failures: dict[str, list[MailDeliveryError]] = field(
        default_factory=dict[str, list[MailDeliveryError]]
    )

    async def send(self, message: OutgoingEmail) -> None:
        pending = self.failures.get(message.to)
        if pending:
            raise pending.pop(0)
        self.sent.append(message)


@dataclass
class Tenant:
    app: FastAPI
    clock: FrozenClock
    org: uuid.UUID
    other_org: uuid.UUID
    project: uuid.UUID
    monitor: uuid.UUID
    admin: httpx.AsyncClient
    member: httpx.AsyncClient
    viewer: httpx.AsyncClient
    outsider: httpx.AsyncClient
    admin_id: uuid.UUID
    member_id: uuid.UUID
    viewer_id: uuid.UUID
    outsider_id: uuid.UUID
    telegram: FakeTelegram
    mailer: FakeMailer

    def url(self, path: str = "") -> str:
        return f"/api/orgs/{self.org}{path}"

    def session(self) -> AsyncSession:
        return self.app.state.sessionmaker()

    def dispatcher(self, **kw: Any) -> Dispatcher:
        return Dispatcher(
            sessionmaker=self.app.state.sessionmaker,
            box=self.app.state.secret_box,
            telegram=self.telegram,
            mailer=self.mailer,
            settings=self.app.state.settings,
            **kw,
        )

    async def post(self, client: httpx.AsyncClient, path: str, body: Any = None) -> httpx.Response:
        return await client.post(self.url(path), json=body, headers=csrf(client))

    async def patch(self, client: httpx.AsyncClient, path: str, body: Any) -> httpx.Response:
        return await client.patch(self.url(path), json=body, headers=csrf(client))

    async def telegram_channel(self, **extra: Any) -> dict[str, Any]:
        body = {
            "type": "TELEGRAM",
            "label": "On-call chat",
            "telegram": {"bot_token": BOT_TOKEN, "chat_id": CHAT_ID},
            **extra,
        }
        response = await self.post(self.admin, "/notification-channels", body)
        assert response.status_code == 201, response.text
        return response.json()

    async def email_channel(self, *recipients: uuid.UUID, **extra: Any) -> dict[str, Any]:
        body = {
            "type": "EMAIL",
            "label": "Team email",
            "recipient_user_ids": [str(r) for r in recipients],
            **extra,
        }
        response = await self.post(self.admin, "/notification-channels", body)
        assert response.status_code == 201, response.text
        return response.json()

    async def check(self, *results: str, monitor: uuid.UUID | None = None, **kw: Any) -> None:
        for result in results:
            self.clock.advance(seconds=60)
            job = await self.claim(monitor or self.monitor)
            assert await self.finish(job, result, **kw) == "recorded"

    async def claim(self, monitor: uuid.UUID) -> Any:
        now = clock.now()
        async with self.session() as s:
            await s.execute(
                update(MonitorSchedule)
                .where(MonitorSchedule.monitor_id == monitor)
                .values(next_due_at=now)
            )
            await s.commit()
            jobs = await claim_jobs(
                s,
                worker_id="w-test",
                capacity=Capacity(10, 10, 10, Counter(), Counter()),
                now=now,
                batch=10,
            )
        [job] = [j for j in jobs if j.monitor_id == monitor]
        return job

    async def finish(self, job: Any, result: str, *, tls_days: float | None = None) -> str:
        failed = result == "FAIL"
        outcome = CheckOutcome(
            result,
            failure_category="HTTP_STATUS_MISMATCH" if failed else None,
            http_status=503 if failed else (200 if result in ("PASS", "SLOW") else None),
            elapsed_ms=42,
            tls_not_after=clock.now() + timedelta(days=tls_days) if tls_days is not None else None,
        )
        async with self.session() as s:
            return await complete_job(s, job, outcome, observed_at=clock.now(), now=clock.now())

    async def outbox(self, **filters: Any) -> list[NotificationOutbox]:
        async with self.session() as s:
            stmt = select(NotificationOutbox).where(NotificationOutbox.organization_id == self.org)
            for key, value in filters.items():
                stmt = stmt.where(getattr(NotificationOutbox, key) == value)
            return list(await s.scalars(stmt.order_by(NotificationOutbox.created_at)))


async def make_tenant(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory, frozen_clock: FrozenClock
) -> Tenant:
    pw = app.state.passwords
    admin_id = await make_user(db, pw, "admin@acme.test")
    member_id = await make_user(db, pw, "member@acme.test")
    viewer_id = await make_user(db, pw, "viewer@acme.test")
    outsider_id = await make_user(db, pw, "owner@globex.test")
    org = await make_org(
        db,
        slug="acme",
        name="Acme",
        created_by=admin_id,
        members={admin_id: OrgRole.ADMIN, member_id: OrgRole.MEMBER, viewer_id: OrgRole.VIEWER},
    )
    other = await make_org(
        db, slug="globex", created_by=outsider_id, members={outsider_id: OrgRole.OWNER}
    )
    await make_verified_domain(db, organization_id=org, fqdn="acme.example", created_by=admin_id)
    project = await make_project(db, organization_id=org, created_by=admin_id)
    clients: list[httpx.AsyncClient] = []
    for email in ("admin@acme.test", "member@acme.test", "viewer@acme.test", "owner@globex.test"):
        client = client_factory()
        assert (await login(client, email)).status_code == 200
        clients.append(client)
    admin, member, viewer, outsider = clients
    created = await admin.post(
        f"/api/orgs/{org}/monitors",
        json=monitor_body(
            project,
            url=f"https://api.acme.example/health?key={SECRET_QUERY}",
            retry_attempts=0,
            name="Payments API",
        ),
        headers=csrf(admin),
    )
    assert created.status_code == 201, created.text
    return Tenant(
        app,
        frozen_clock,
        org,
        other,
        project,
        uuid.UUID(created.json()["id"]),
        admin,
        member,
        viewer,
        outsider,
        admin_id,
        member_id,
        viewer_id,
        outsider_id,
        FakeTelegram(),
        FakeMailer(),
    )


TenantFactory = Callable[[], Tenant]


@pytest.fixture
async def tenant(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory, frozen_clock: FrozenClock
) -> Tenant:
    return await make_tenant(app, db, client_factory, frozen_clock)
