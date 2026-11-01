"""Integration harness against the approved disposable database ``sentinelops_test``.

Set SENTINELOPS_TEST_DATABASE_URL (owner role, localhost only). Without it these tests are
skipped, unless SENTINELOPS_REQUIRE_INTEGRATION=1 (CI), in which case the run fails.
The session fixture runs every safety check before applying any migration.
"""

import asyncio
import base64
import os
import secrets
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from alembic import command
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy import make_url, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

from sentinelops import clock
from sentinelops.api.app import create_app
from sentinelops.config import Environment, Settings
from sentinelops.mail import MailDeliveryError, OutgoingEmail
from tests.support.disposable_db import (
    UnsafeDatabaseError,
    alembic_config,
    check_all_revisions,
    current_revision,
    ensure_disposable,
    verify_target,
)

ORIGIN = "http://testserver"
APP_LOGIN_ROLE = "sentinelops_app_test"
RESET_SQL = [
    "TRUNCATE platform_admin_recovery_code, platform_admin_mfa, "
    "session, auth_token, auth_throttle, platform_admin_invitation, platform_admin, "
    "audit_event, worker_heartbeat, notification_delivery, notification_outbox, "
    "notification_route, notification_channel_recipient, notification_channel, "
    "status_page_snapshot, status_page_monitor, status_page, "
    "incident_event, incident, measurement, "
    "hourly_monitor_rollup, monitor_health, "
    "monitor_schedule, monitor, verified_domain, project, org_invitation, user_preference, "
    "organization_member, organization_limit, organization",
    "UPDATE platform_settings SET default_max_monitors = 20, min_interval_seconds = 60, "
    "max_timeout_ms = 15000, max_retry_attempts = 2, max_custom_headers = 5, "
    "validation_max_bytes = 65536, check_now_per_monitor_seconds = 60, "
    "check_now_per_org_hour = 30, default_max_status_pages = 3, default_max_channels = 10, "
    "updated_by = NULL, version = 1",
    "DELETE FROM app_user",
]


@dataclass(frozen=True)
class DisposableDatabase:
    owner_url: str
    app_url: str


async def _create_app_login_role(owner_url: str) -> str:
    """A login role that is only a member of the NOLOGIN app role, so tests run least-privilege."""
    password = secrets.token_hex(24)  # generated per run, never stored
    engine = create_async_engine(owner_url)
    try:
        async with engine.begin() as conn:
            exists = await conn.scalar(
                text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": APP_LOGIN_ROLE}
            )
            verb = "ALTER" if exists else "CREATE"
            await conn.execute(text(f"{verb} ROLE {APP_LOGIN_ROLE} LOGIN PASSWORD '{password}'"))
            await conn.execute(text(f"GRANT sentinelops_app TO {APP_LOGIN_ROLE}"))
    finally:
        await engine.dispose()
    return (
        make_url(owner_url)
        .set(username=APP_LOGIN_ROLE, password=password)
        .render_as_string(hide_password=False)
    )


@pytest.fixture(scope="session")
def test_database() -> DisposableDatabase:
    owner_url = os.environ.get("SENTINELOPS_TEST_DATABASE_URL")
    if not owner_url:
        if os.environ.get("SENTINELOPS_REQUIRE_INTEGRATION") == "1":
            pytest.fail("SENTINELOPS_TEST_DATABASE_URL is required for integration tests")
        pytest.skip("SENTINELOPS_TEST_DATABASE_URL not set")
    config = alembic_config(owner_url)
    try:
        verify_target(owner_url)
        asyncio.run(ensure_disposable(owner_url))
        check_all_revisions(owner_url)
        # Earlier gates' migrations (0001-0008) must be applied, in order, before G7's.
        if asyncio.run(current_revision(owner_url)) is None:
            command.upgrade(config, "0008")
        if asyncio.run(current_revision(owner_url)) not in {"0008", "0009"}:
            raise UnsafeDatabaseError(
                "Migrations 0001-0008 are not applied; refusing G7 migrations"
            )
    except UnsafeDatabaseError as exc:
        pytest.exit(f"Unsafe test database, stopping before migration: {exc}", returncode=3)
    # Migration verification: upgrade to head, full downgrade, upgrade again.
    command.upgrade(config, "head")
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    return DisposableDatabase(owner_url, asyncio.run(_create_app_login_role(owner_url)))


@pytest.fixture
async def owner_engine(test_database: DisposableDatabase) -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(test_database.owner_url)
    async with engine.begin() as conn:
        for statement in RESET_SQL:
            await conn.execute(text(statement))
    yield engine
    await engine.dispose()


class FrozenClock:
    def __init__(self) -> None:
        self.current = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, **kwargs: float) -> None:
        self.current += timedelta(**kwargs)


@pytest.fixture
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> FrozenClock:
    fake = FrozenClock()
    monkeypatch.setattr(clock, "now", fake)
    return fake


@dataclass
class RecordingMailer:
    messages: list[OutgoingEmail] = field(default_factory=list[OutgoingEmail])
    fail: bool = False

    async def send(self, message: OutgoingEmail) -> None:
        if self.fail:
            raise MailDeliveryError
        self.messages.append(message)


@pytest.fixture
def mailer() -> RecordingMailer:
    return RecordingMailer()


class FakeTxt:
    """DNS TXT records for domain verification tests (no real DNS)."""

    def __init__(self) -> None:
        self.records: dict[str, list[str]] = {}

    async def __call__(self, name: str) -> list[str]:
        return list(self.records.get(name, []))


@pytest.fixture
def txt() -> FakeTxt:
    return FakeTxt()


@pytest.fixture(scope="session")
def secret_key() -> SecretStr:
    return SecretStr(base64.b64encode(os.urandom(32)).decode())  # per run, never stored


@pytest.fixture
def settings(test_database: DisposableDatabase, secret_key: SecretStr) -> Settings:
    return Settings(
        env=Environment.TEST,
        database_url=SecretStr(test_database.app_url),
        allowed_origins=[ORIGIN],
        public_base_url="http://localhost:5173",
        password_hash_time_cost=1,
        password_hash_memory_kib=1024,
        secret_keys={"test": secret_key},
        secret_active_key_id="test",
        mfa_keys={"mfa-test": secret_key},
        mfa_active_key_id="mfa-test",
    )


@pytest.fixture
async def app(
    settings: Settings, mailer: RecordingMailer, txt: FakeTxt, owner_engine: AsyncEngine
) -> AsyncIterator[FastAPI]:
    del owner_engine  # requested for the per-test reset
    application = create_app(settings, mailer=mailer, txt_lookup=txt)
    async with application.router.lifespan_context(application):
        yield application


ClientFactory = Callable[[], httpx.AsyncClient]


@pytest.fixture
async def client_factory(app: FastAPI) -> AsyncIterator[ClientFactory]:
    """Independent browser-like clients (separate cookie jars)."""
    clients: list[httpx.AsyncClient] = []

    def make() -> httpx.AsyncClient:
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=ORIGIN,
            headers={"Origin": ORIGIN},
        )
        clients.append(client)
        return client

    yield make
    for client in clients:
        await client.aclose()


@pytest.fixture
def client(client_factory: ClientFactory) -> httpx.AsyncClient:
    return client_factory()


@pytest.fixture
async def db(app: FastAPI) -> AsyncIterator[AsyncSession]:
    async with app.state.sessionmaker() as session:
        yield session
