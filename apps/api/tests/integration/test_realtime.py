"""G6 dashboard SSE (FR-UI-005, AC-002): per-organization delivery, membership re-validation,
suspension, reconnect and resync. Streams are bounded by short test settings."""

import asyncio
import json
import time
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinelops.platform.organizations import suspend_organization
from sentinelops.realtime.hub import QUEUE_SIZE, RESYNC, Event, Subscription
from sentinelops.realtime.routes import SseSettings
from tests.integration.g5 import SECRET_QUERY, Tenant, tenant
from tests.integration.helpers import csrf

pytestmark = pytest.mark.integration
__all__ = ["tenant"]


@pytest.fixture
def t(tenant: Tenant) -> Tenant:
    tenant.app.state.sse_settings = SseSettings(
        heartbeat_seconds=0.1, revalidate_seconds=0.2, max_seconds=2.0, retry_ms=100
    )
    return tenant


def frames(body: str) -> list[tuple[str, dict[str, Any]]]:
    parsed: list[tuple[str, dict[str, Any]]] = []
    for block in body.split("\n\n"):
        lines = dict(
            line.split(": ", 1) for line in block.splitlines() if line and not line.startswith(":")
        )
        if "event" in lines:
            parsed.append((lines["event"], json.loads(lines.get("data", "{}"))))
    return parsed


async def open_stream(client: httpx.AsyncClient, url: str) -> asyncio.Task[httpx.Response]:
    task = asyncio.create_task(client.get(url))
    await asyncio.sleep(0.3)  # connected and subscribed
    return task


async def test_events_reach_only_their_organization(t: Tenant) -> None:
    acme = await open_stream(t.viewer, t.url("/events"))
    other = await open_stream(t.outsider, f"/api/orgs/{t.other_org}/events")
    await t.check("FAIL", "FAIL", "FAIL")
    response = await acme
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-store"
    events = frames(response.text)
    names = [name for name, _ in events]
    assert names[0] == "ready" and names[-1] == "reconnect"
    assert names.count("check.recorded") == 3
    assert "monitor.health" in names and "incident.opened" in names
    opened = next(data for name, data in events if name == "incident.opened")
    assert opened["monitor_id"] == str(t.monitor) and opened["type"] == "OUTAGE"
    assert set(opened) == {"incident_id", "monitor_id", "type", "severity", "status"}
    assert SECRET_QUERY not in response.text and "api.acme.example" not in response.text
    assert "Payments API" not in response.text
    foreign = [name for name, _ in frames((await other).text)]
    assert foreign == ["ready", "reconnect"]  # nothing from the other organization


async def test_unauthorized_streams_are_refused(t: Tenant) -> None:
    assert (await t.outsider.get(t.url("/events"))).status_code == 404
    unauthenticated = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=t.app), base_url="http://testserver"
    )
    async with unauthenticated:
        assert (await unauthenticated.get(t.url("/events"))).status_code == 401


async def test_removed_member_stream_is_revoked_within_the_revalidation_interval(t: Tenant) -> None:
    stream = await open_stream(t.viewer, t.url("/events"))
    started = time.monotonic()
    removed = await t.admin.delete(t.url(f"/members/{t.viewer_id}"), headers=csrf(t.admin))
    assert removed.status_code in (200, 204)
    response = await stream
    assert [name for name, _ in frames(response.text)][-1] == "revoked"
    assert time.monotonic() - started < 1.5  # well before max_seconds
    assert (await t.viewer.get(t.url("/events"))).status_code == 404  # reconnect refused


async def test_logout_revokes_the_stream(t: Tenant) -> None:
    stream = await open_stream(t.member, t.url("/events"))
    await t.member.post("/api/auth/logout", headers=csrf(t.member))
    assert [name for name, _ in frames((await stream).text)][-1] == "revoked"


async def test_suspended_organization_stream_is_revoked(t: Tenant) -> None:
    stream = await open_stream(t.viewer, t.url("/events"))
    async with t.session() as s:
        await suspend_organization(s, actor_id=t.admin_id, org_id=t.org, reason="review")
    assert [name for name, _ in frames((await stream).text)][-1] == "revoked"
    refused = await t.viewer.get(t.url("/events"))
    assert refused.status_code == 403 and refused.json()["error"]["code"] == "ORG_SUSPENDED"


async def test_listener_reconnects_and_tells_clients_to_resync(
    t: Tenant, owner_engine: AsyncEngine
) -> None:
    t.app.state.sse_settings = SseSettings(
        heartbeat_seconds=0.1, revalidate_seconds=5, max_seconds=4.0, retry_ms=100
    )
    stream = await open_stream(t.viewer, t.url("/events"))
    async with owner_engine.begin() as conn:  # drop the API's LISTEN connection
        await conn.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE query ILIKE 'LISTEN%' AND pid <> pg_backend_pid()"
            )
        )
    await asyncio.sleep(1.0)
    await t.check("PASS")  # delivered over the re-established connection
    names = [name for name, _ in frames((await stream).text)]
    assert "resync" in names
    assert names.index("resync") < names.index("check.recorded")


async def test_rolled_back_changes_publish_nothing(t: Tenant) -> None:
    stream = await open_stream(t.viewer, t.url("/events"))
    async with t.session() as s:
        await s.execute(
            text("SELECT pg_notify('sentinelops_events', :p)"),
            {"p": json.dumps({"org": str(t.org), "event": "check.recorded", "data": {}})},
        )
        await s.rollback()
    names = [name for name, _ in frames((await stream).text)]
    assert "check.recorded" not in names


def test_slow_subscribers_get_a_resync_instead_of_unbounded_backlog() -> None:
    import uuid

    sub = Subscription(uuid.uuid4())
    for i in range(QUEUE_SIZE + 5):
        sub.offer(Event("check.recorded", {"n": i}))
    assert sub.queue.get_nowait() == RESYNC  # backlog dropped; newer events follow the resync
    assert sub.queue.qsize() == 4
