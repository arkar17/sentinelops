"""The opt-in fictional demo seed (G7): refuses unsafe targets and builds a coherent dataset."""

from typing import Any

import pytest
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.cli.demo import DemoRefusedError, check_database_name, seed_demo
from sentinelops.identity.models import AppUser
from sentinelops.incidents.models import Incident
from sentinelops.measurements.models import HourlyMonitorRollup, Measurement
from sentinelops.notifications.models import NotificationDelivery
from sentinelops.scheduler.models import MonitorSchedule
from sentinelops.status_pages.models import StatusPageSnapshot
from sentinelops.tenancy.models import Organization
from tests.integration.conftest import ClientFactory

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "name", ["sentinelops", "sentinelops_prod", "demo", "sentinelops_test2", None]
)
def test_only_demo_databases_are_accepted(name: str | None) -> None:
    with pytest.raises(DemoRefusedError):
        check_database_name(name)
    check_database_name("acme_demo")


async def test_seed_builds_two_isolated_orgs_and_refuses_a_second_run(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory
) -> None:
    accounts = await seed_demo(db, app.state.settings, app.state.passwords, app.state.secret_box)
    assert len(accounts.credentials) == 7
    passwords = {p for _, _, p in accounts.credentials}
    hashes = set(await db.scalars(select(AppUser.password_hash)))
    assert passwords.isdisjoint(hashes) and all(h and h.startswith("$argon2id$") for h in hashes)

    async def count(model: type[Any]) -> int:
        return int(await db.scalar(select(func.count()).select_from(model)) or 0)

    assert await count(Organization) == 2
    assert await count(Measurement) == 3 * 24 * 60
    assert await count(Incident) == 4
    assert await count(NotificationDelivery) > 0
    assert await count(HourlyMonitorRollup) > 0
    assert await count(StatusPageSnapshot) == 1
    assert min(await db.scalars(select(MonitorSchedule.next_due_at))).year >= 2030  # never probed
    with pytest.raises(DemoRefusedError):
        await seed_demo(db, app.state.settings, app.state.passwords, app.state.secret_box)
    # Cross-organization isolation holds for the demo users.
    member = next(e for e, _, _ in accounts.credentials if e.startswith("mia."))
    password = next(p for e, _, p in accounts.credentials if e == member)
    client = client_factory()
    await client.post("/api/auth/login", json={"email": member, "password": password})
    orgs = (await client.get("/api/me/organizations")).json()["organizations"]
    assert [o["slug"] for o in orgs] == ["contoso"]
    northwind = await db.scalar(select(Organization.id).where(Organization.slug == "northwind"))
    assert (await client.get(f"/api/orgs/{northwind}/incidents")).status_code == 404
    public = await client_factory().get("/api/status/northwind-status")
    assert public.status_code == 200 and "pay.northwind.example" not in public.text
