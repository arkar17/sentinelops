"""Browser E2E harness: the real SentinelOps API plus test-only controls under /__e2e.

Runs only against the guarded disposable database (``SENTINELOPS_TEST_DATABASE_URL``, a local
database named exactly ``sentinelops_test``): it verifies the target, applies the approved
migrations, resets the data and starts uvicorn on 127.0.0.1:8001. Probes, DNS, email and
Telegram are fakes, so nothing leaves the machine. Never part of the deployed package.

    uv run python -m tests.e2e.server
"""

import asyncio
import base64
import os
import secrets
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import uvicorn
from alembic import command
from fastapi import APIRouter, FastAPI
from pydantic import BaseModel, SecretStr
from sqlalchemy import make_url, select, text, update
from sqlalchemy.ext.asyncio import create_async_engine

from sentinelops import clock
from sentinelops.api.app import create_app
from sentinelops.catalog.models import Monitor, MonitorLifecycle
from sentinelops.config import Environment, Settings
from sentinelops.mail import OutgoingEmail
from sentinelops.notifications.dispatcher import Dispatcher
from sentinelops.notifications.telegram import SendResult
from sentinelops.platform.service import bootstrap_system_admin
from sentinelops.probes.http.engine import CheckOutcome
from sentinelops.scheduler.models import MonitorSchedule
from sentinelops.scheduler.service import Capacity, claim_jobs, complete_job
from tests.support.disposable_db import (
    alembic_config,
    check_all_revisions,
    ensure_disposable,
    verify_target,
)

API_PORT = int(os.environ.get("SENTINELOPS_E2E_API_PORT", "8001"))
WEB_ORIGIN = os.environ.get("SENTINELOPS_E2E_WEB_ORIGIN", "http://127.0.0.1:5174")
APP_ROLE_LOGIN = "sentinelops_app_e2e"
TABLES = (
    "platform_admin_recovery_code, platform_admin_mfa, session, auth_token, auth_throttle, "
    "platform_admin_invitation, platform_admin, audit_event, worker_heartbeat, "
    "notification_delivery, notification_outbox, notification_route, "
    "notification_channel_recipient, notification_channel, status_page_snapshot, "
    "status_page_monitor, status_page, incident_event, incident, measurement, "
    "hourly_monitor_rollup, monitor_health, monitor_schedule, monitor, verified_domain, project, "
    "org_invitation, user_preference, organization_member, organization_limit, organization"
)


@dataclass
class Mailbox:
    messages: list[OutgoingEmail] = field(default_factory=list[OutgoingEmail])

    async def send(self, message: OutgoingEmail) -> None:
        self.messages.append(message)


@dataclass
class Txt:
    records: dict[str, list[str]] = field(default_factory=dict[str, list[str]])

    async def __call__(self, name: str) -> list[str]:
        return list(self.records.get(name, []))


@dataclass
class Telegram:
    sent: list[str] = field(default_factory=list[str])

    async def send_message(self, bot_token: str, chat_id: str, text: str) -> SendResult:
        self.sent.append(text)
        return SendResult("SENT", ok=True, provider_ref=str(len(self.sent)))


async def prepare_database(owner_url: str) -> str:
    """Safety checks, approved migrations, data reset, least-privilege login role."""
    verify_target(owner_url)
    await ensure_disposable(owner_url)
    check_all_revisions(owner_url)
    await asyncio.to_thread(command.upgrade, alembic_config(owner_url), "head")
    password = secrets.token_hex(24)  # generated per run, never stored
    engine = create_async_engine(owner_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(f"TRUNCATE {TABLES}"))
            await conn.execute(text("DELETE FROM app_user"))
            exists = await conn.scalar(
                text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": APP_ROLE_LOGIN}
            )
            verb = "ALTER" if exists else "CREATE"
            await conn.execute(text(f"{verb} ROLE {APP_ROLE_LOGIN} LOGIN PASSWORD '{password}'"))
            await conn.execute(text(f"GRANT sentinelops_app TO {APP_ROLE_LOGIN}"))
    finally:
        await engine.dispose()
    return (
        make_url(owner_url)
        .set(username=APP_ROLE_LOGIN, password=password)
        .render_as_string(hide_password=False)
    )


def build(app_url: str) -> FastAPI:
    def key() -> SecretStr:
        return SecretStr(base64.b64encode(os.urandom(32)).decode())

    settings = Settings(
        env=Environment.TEST,
        database_url=SecretStr(app_url),
        allowed_origins=[WEB_ORIGIN],
        public_base_url=WEB_ORIGIN,
        password_hash_time_cost=1,
        password_hash_memory_kib=1024,
        secret_keys={"e2e": key()},
        secret_active_key_id="e2e",
        mfa_keys={"e2e": key()},
        mfa_active_key_id="e2e",
        admin_mfa_required=True,  # exercise the production MFA policy end to end
    )
    mailbox, txt, telegram = Mailbox(), Txt(), Telegram()
    app = create_app(settings, mailer=mailbox, txt_lookup=txt)
    controls = APIRouter(prefix="/__e2e")

    class Bootstrap(BaseModel):
        email: str

    class Dns(BaseModel):
        name: str
        values: list[str]

    class Checks(BaseModel):
        result: str
        rounds: int = 1

    @controls.post("/bootstrap")
    async def bootstrap(body: Bootstrap) -> dict[str, str]:
        async with app.state.sessionmaker() as db:
            return {"activation_url": await bootstrap_system_admin(db, settings, email=body.email)}

    @controls.get("/mail")
    async def mail(to: str | None = None) -> list[dict[str, str]]:
        return [
            {"to": m.to, "subject": m.subject, "body": m.body}
            for m in mailbox.messages
            if to is None or m.to.lower() == to.lower()
        ]

    @controls.put("/dns")
    async def dns(body: Dns) -> dict[str, int]:
        txt.records[body.name] = body.values
        return {"records": len(txt.records)}

    @controls.post("/checks")
    async def checks(body: Checks) -> dict[str, Any]:
        """Simulated probe results through the real claim/complete path (no network)."""
        recorded: Counter[str] = Counter()
        jobs: list[Any] = []
        for _ in range(body.rounds):
            clock_now = clock.now()
            async with app.state.sessionmaker() as db:
                await db.execute(
                    update(MonitorSchedule)
                    .where(
                        MonitorSchedule.monitor_id.in_(
                            select(Monitor.id).where(Monitor.lifecycle == MonitorLifecycle.ACTIVE)
                        )
                    )
                    .values(next_due_at=clock_now - timedelta(seconds=1), lease_until=None)
                )
                await db.commit()
                jobs = await claim_jobs(
                    db,
                    worker_id="e2e",
                    capacity=Capacity(100, 100, 100, Counter(), Counter()),
                    now=clock_now,
                    batch=100,
                )
            failed = body.result == "FAIL"
            outcome = CheckOutcome(
                body.result,
                failure_category="HTTP_STATUS_MISMATCH" if failed else None,
                http_status=503 if failed else 200,
                elapsed_ms=90 if body.result == "PASS" else (1500 if body.result == "SLOW" else 40),
                tls_not_after=clock_now + timedelta(days=60),
            )
            for job in jobs:
                async with app.state.sessionmaker() as db:
                    status = await complete_job(
                        db, job, outcome, observed_at=clock.now(), now=clock.now()
                    )
                recorded[status] += 1
            await asyncio.sleep(0.01)  # distinct observation times
        return {"recorded": dict(recorded), "monitors": len(jobs)}

    @controls.post("/notifier")
    async def notifier() -> dict[str, Any]:
        dispatcher = Dispatcher(
            sessionmaker=app.state.sessionmaker,
            box=app.state.secret_box,
            telegram=telegram,
            mailer=mailbox,
            settings=settings,
        )
        return {"results": await dispatcher.run_once()}

    @controls.get("/telegram")
    async def telegram_sent() -> list[str]:
        return telegram.sent

    app.include_router(controls)
    return app


def main() -> None:
    owner_url = os.environ["SENTINELOPS_TEST_DATABASE_URL"]
    app_url = asyncio.run(prepare_database(owner_url))
    uvicorn.run(build(app_url), host="127.0.0.1", port=API_PORT, log_level="warning")


if __name__ == "__main__":
    main()
