"""Monitor catalog: limits, permissions, secrets, lifecycle, history and isolation (G3)."""

import asyncio
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from sentinelops import clock
from sentinelops.db.base import new_id
from sentinelops.measurements.models import Measurement
from sentinelops.tenancy.models import OrgRole
from tests.integration.conftest import ClientFactory
from tests.integration.helpers import (
    csrf,
    login,
    make_org,
    make_project,
    make_user,
    make_verified_domain,
    monitor_body,
)

pytestmark = pytest.mark.integration

SECRET_QUERY = "s3cr3t-q"  # noqa: S105  # fictional query token


@dataclass
class Org:
    id: uuid.UUID
    project: uuid.UUID
    clients: dict[str, httpx.AsyncClient]

    def url(self, path: str = "") -> str:
        return f"/api/orgs/{self.id}{path}"


async def _org(app: FastAPI, db: AsyncSession, factory: ClientFactory, slug: str, fqdn: str) -> Org:
    roles = {
        "owner": OrgRole.OWNER,
        "admin": OrgRole.ADMIN,
        "member": OrgRole.MEMBER,
        "viewer": OrgRole.VIEWER,
    }
    users = {
        name: await make_user(db, app.state.passwords, f"{name}@{slug}.test") for name in roles
    }
    org = await make_org(
        db, slug=slug, created_by=users["owner"], members={users[n]: r for n, r in roles.items()}
    )
    await make_verified_domain(db, organization_id=org, fqdn=fqdn, created_by=users["owner"])
    project = await make_project(db, organization_id=org, created_by=users["owner"])
    clients: dict[str, httpx.AsyncClient] = {}
    for name in roles:
        clients[name] = factory()
        await login(clients[name], f"{name}@{slug}.test")
    return Org(org, project, clients)


@pytest.fixture
async def acme(app: FastAPI, db: AsyncSession, client_factory: ClientFactory) -> Org:
    return await _org(app, db, client_factory, "acme", "acme.example")


async def _create(org: Org, role: str = "admin", **extra: Any) -> httpx.Response:
    client = org.clients[role]
    return await client.post(
        org.url("/monitors"), json=monitor_body(org.project, **extra), headers=csrf(client)
    )


async def test_create_active_monitor_with_encrypted_url(
    acme: Org, owner_engine: AsyncEngine
) -> None:
    response = await _create(acme)
    assert response.status_code == 201, response.text
    monitor = response.json()
    assert monitor["lifecycle"] == "ACTIVE"
    assert monitor["health_state"] == "UNKNOWN"
    assert monitor["config"]["display_url"] == "https://api.acme.example/health"
    assert monitor["config"]["expected_status"] == [[200, 299]]
    assert SECRET_QUERY not in response.text
    async with owner_engine.connect() as conn:
        row = (await conn.execute(text("SELECT * FROM monitor"))).mappings().one()
        assert SECRET_QUERY not in str(dict(row))
        schedule = (await conn.execute(text("SELECT count(*) FROM monitor_schedule"))).scalar()
        health = (await conn.execute(text("SELECT count(*) FROM monitor_health"))).scalar()
    assert (schedule, health) == (1, 1)


async def test_edit_form_reveals_url_only_to_editors(acme: Org) -> None:
    monitor_id = (await _create(acme)).json()["id"]
    edit = await acme.clients["admin"].get(acme.url(f"/monitors/{monitor_id}/edit"))
    assert edit.status_code == 200
    assert edit.json()["url"].endswith(f"?key={SECRET_QUERY}")
    assert (
        await acme.clients["member"].get(acme.url(f"/monitors/{monitor_id}/edit"))
    ).status_code == 403
    member_view = (await acme.clients["member"].get(acme.url(f"/monitors/{monitor_id}"))).json()
    assert member_view["config"]["display_url"] == "https://api.acme.example/health"
    viewer_view = (await acme.clients["viewer"].get(acme.url(f"/monitors/{monitor_id}"))).json()
    assert viewer_view["config"] is None
    assert viewer_view["hostname"] == "api.acme.example"


async def test_headers_are_encrypted_and_write_only(acme: Org, owner_engine: AsyncEngine) -> None:
    monitor_id = (await _create(acme)).json()["id"]
    admin = acme.clients["admin"]
    headers = {
        "headers": [
            {"name": "Authorization", "value": "Bearer tok-123"},
            {"name": "X-Api-Key", "value": "k-456"},
        ]
    }
    response = await admin.put(
        acme.url(f"/monitors/{monitor_id}/headers"), json=headers, headers=csrf(admin)
    )
    assert response.status_code == 200
    assert response.json()["config"]["header_count"] == 2
    for path in (f"/monitors/{monitor_id}", f"/monitors/{monitor_id}/edit", "/monitors", "/audit"):
        body = (await admin.get(acme.url(path))).text
        for secret in ("tok-123", "k-456", "Authorization", "X-Api-Key"):
            assert secret not in body, (path, secret)
    async with owner_engine.connect() as conn:
        dump = str((await conn.execute(text("SELECT * FROM monitor"))).all())
        audit = str((await conn.execute(text("SELECT * FROM audit_event"))).all())
    assert "tok-123" not in dump and "Authorization" not in dump
    assert "tok-123" not in audit
    member = acme.clients["member"]
    assert (
        await member.put(
            acme.url(f"/monitors/{monitor_id}/headers"), json=headers, headers=csrf(member)
        )
    ).status_code == 403
    cleared = await admin.put(
        acme.url(f"/monitors/{monitor_id}/headers"), json={"headers": []}, headers=csrf(admin)
    )
    assert cleared.json()["config"]["header_count"] == 0


@pytest.mark.parametrize(
    "headers",
    [
        [{"name": "Host", "value": "169.254.169.254"}],
        [{"name": "X-Forwarded-For", "value": "10.0.0.1"}],
        [{"name": "Proxy-Authorization", "value": "x"}],
        [{"name": "User-Agent", "value": "x"}],
        [{"name": "Bad Name", "value": "x"}],
        [{"name": "X-Ok", "value": "line\r\nInjected: 1"}],
        [{"name": "X-A", "value": "1"}, {"name": "x-a", "value": "2"}],
        [{"name": f"X-H{i}", "value": "v"} for i in range(6)],
    ],
)
async def test_unsafe_headers_rejected(acme: Org, headers: list[dict[str, str]]) -> None:
    monitor_id = (await _create(acme)).json()["id"]
    admin = acme.clients["admin"]
    response = await admin.put(
        acme.url(f"/monitors/{monitor_id}/headers"), json={"headers": headers}, headers=csrf(admin)
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"url": "http://127.0.0.1/"}, "URL_NOT_ALLOWED"),
        ({"url": "http://169.254.169.254/latest/meta-data/"}, "URL_NOT_ALLOWED"),
        ({"url": "https://api.acme.example:8443/"}, "URL_NOT_ALLOWED"),
        ({"url": "https://user:pw@api.acme.example/"}, "URL_NOT_ALLOWED"),
        (
            {"method": "HEAD", "validation": {"type": "substring", "value": "ok"}},
            "VALIDATION_NEEDS_GET",
        ),
        ({"expected_status": ["700"]}, "INVALID_EXPECTED_STATUS"),
        ({"validation": {"type": "json_path", "path": "$..x", "equals": 1}}, "INVALID_VALIDATION"),
    ],
)
async def test_invalid_monitor_configuration(
    acme: Org, overrides: dict[str, Any], code: str
) -> None:
    response = await _create(acme, **overrides)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == code


async def test_member_and_viewer_cannot_create_monitors(acme: Org) -> None:
    assert (await _create(acme, role="member")).status_code == 403  # OD-04
    assert (await _create(acme, role="viewer")).status_code == 403


async def test_monitor_limit_including_concurrent_creates(
    acme: Org, owner_engine: AsyncEngine
) -> None:
    async with owner_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO organization_limit"
                " (organization_id, max_monitors, updated_at, version)"
                " VALUES (:o, 3, now(), 1)"
            ),
            {"o": acme.id},
        )
    results = await asyncio.gather(*(_create(acme) for _ in range(6)))
    codes = sorted(r.status_code for r in results)
    assert codes == [201, 201, 201, 409, 409, 409]
    archived = next(r for r in results if r.status_code == 201).json()["id"]
    admin = acme.clients["admin"]
    await admin.post(acme.url(f"/monitors/{archived}/archive"), headers=csrf(admin))
    assert (await _create(acme)).status_code == 201  # archived monitors free a slot
    unarchive = await admin.post(acme.url(f"/monitors/{archived}/unarchive"), headers=csrf(admin))
    assert unarchive.status_code == 409


async def test_interval_and_timeout_limits(acme: Org, owner_engine: AsyncEngine) -> None:
    async with owner_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO organization_limit"
                " (organization_id, min_interval_seconds, updated_at, version)"
                " VALUES (:o, 120, now(), 1)"
            ),
            {"o": acme.id},
        )
        await conn.execute(
            text("UPDATE platform_settings SET max_timeout_ms = 5000, max_retry_attempts = 1")
        )
    assert (await _create(acme, interval_seconds=60)).json()["error"][
        "code"
    ] == "INTERVAL_TOO_SHORT"
    assert (await _create(acme, interval_seconds=120, timeout_ms=10000)).json()["error"][
        "code"
    ] == "TIMEOUT_TOO_LONG"
    assert (await _create(acme, interval_seconds=120, timeout_ms=5000, retry_attempts=2)).json()[
        "error"
    ]["code"] == "TOO_MANY_RETRIES"
    assert (
        await _create(acme, interval_seconds=120, timeout_ms=5000, retry_attempts=1)
    ).status_code == 201
    assert (await _create(acme, interval_seconds=45)).status_code == 422


async def test_lifecycle_transitions(acme: Org) -> None:
    admin = acme.clients["admin"]
    monitor_id = (await _create(acme)).json()["id"]
    paused = await admin.post(acme.url(f"/monitors/{monitor_id}/pause"), headers=csrf(admin))
    assert (paused.json()["lifecycle"], paused.json()["paused_reason"]) == ("PAUSED", "USER")
    resumed = await admin.post(acme.url(f"/monitors/{monitor_id}/resume"), headers=csrf(admin))
    assert resumed.json()["lifecycle"] == "ACTIVE"
    archived = await admin.post(acme.url(f"/monitors/{monitor_id}/archive"), headers=csrf(admin))
    assert archived.json()["lifecycle"] == "ARCHIVED"
    assert (
        await admin.post(acme.url(f"/monitors/{monitor_id}/pause"), headers=csrf(admin))
    ).status_code == 409
    assert (await admin.get(acme.url("/monitors"))).json() == []
    assert len((await admin.get(acme.url("/monitors?include_archived=true"))).json()) == 1
    member = acme.clients["member"]
    assert (
        await member.post(acme.url(f"/monitors/{monitor_id}/unarchive"), headers=csrf(member))
    ).status_code == 403


async def test_edit_requires_current_version_and_resets_health(acme: Org) -> None:
    admin = acme.clients["admin"]
    created = (await _create(acme)).json()
    body = monitor_body(
        acme.project, url="https://status.acme.example/", version=created["version"], name="Status"
    )
    updated = await admin.patch(
        acme.url(f"/monitors/{created['id']}"), json=body, headers=csrf(admin)
    )
    assert updated.status_code == 200
    assert updated.json()["config"]["display_url"] == "https://status.acme.example/"
    stale = await admin.patch(
        acme.url(f"/monitors/{created['id']}"), json=body, headers=csrf(admin)
    )
    assert stale.status_code == 409


async def test_check_now_rules(acme: Org) -> None:
    monitor_id = (await _create(acme)).json()["id"]
    member, viewer = acme.clients["member"], acme.clients["viewer"]
    path = acme.url(f"/monitors/{monitor_id}/check-now")
    assert (await viewer.post(path, headers=csrf(viewer))).status_code == 403
    assert (await member.post(path, headers=csrf(member))).status_code == 202
    limited = await member.post(path, headers=csrf(member))
    assert limited.status_code == 429
    admin = acme.clients["admin"]
    await admin.post(acme.url(f"/monitors/{monitor_id}/pause"), headers=csrf(admin))
    assert (await admin.post(path, headers=csrf(admin))).status_code == 409


async def test_measurement_history_is_bounded(acme: Org, db: AsyncSession) -> None:
    monitor_id = uuid.UUID((await _create(acme)).json()["id"])
    now = clock.now()
    for age in (timedelta(days=40), timedelta(days=10), timedelta(hours=1)):
        db.add(
            Measurement(
                id=new_id(),
                organization_id=acme.id,
                monitor_id=monitor_id,
                trigger="SCHEDULED",
                observed_at=now - age,
                ingested_at=now - age,
                result="PASS",
                http_status=200,
                elapsed_ms=120,
                attempt_count=1,
            )
        )
    await db.commit()
    viewer = acme.clients["viewer"]
    default = (await viewer.get(acme.url(f"/monitors/{monitor_id}/measurements"))).json()
    assert len(default) == 1  # last 24 hours by default
    since = (now - timedelta(days=90)).isoformat()
    wide = (
        await viewer.get(acme.url(f"/monitors/{monitor_id}/measurements"), params={"since": since})
    ).json()
    assert len(wide) == 2  # never older than the 30-day raw window
    assert set(wide[0]) == {
        "id", "trigger", "scheduled_for", "observed_at", "result", "failure_category",
        "http_status", "elapsed_ms", "attempt_count", "tls_not_after",
    }  # fmt: skip
    too_many = await viewer.get(
        acme.url(f"/monitors/{monitor_id}/measurements"), params={"limit": 501}
    )
    assert too_many.status_code == 422


async def test_monitors_and_measurements_are_tenant_isolated(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory, acme: Org
) -> None:
    rival = await _org(app, db, client_factory, "rival", "rival.example")
    rival_monitor = (await _create(rival, url="https://api.rival.example/")).json()["id"]
    attacker = acme.clients["owner"]
    base = acme.url(f"/monitors/{rival_monitor}")
    for method, path, body in [
        ("GET", base, None),
        ("GET", f"{base}/edit", None),
        ("GET", f"{base}/measurements", None),
        ("PATCH", base, monitor_body(acme.project, version=1)),
        ("PUT", f"{base}/headers", {"headers": []}),
        ("POST", f"{base}/pause", None),
        ("POST", f"{base}/resume", None),
        ("POST", f"{base}/archive", None),
        ("POST", f"{base}/check-now", None),
    ]:
        response = await attacker.request(method, path, json=body, headers=csrf(attacker))
        assert response.status_code == 404, (method, path)
    foreign_project = await attacker.post(
        acme.url("/monitors"), json=monitor_body(rival.project), headers=csrf(attacker)
    )
    assert foreign_project.status_code == 404
    assert (await attacker.get(f"/api/orgs/{rival.id}/monitors")).status_code == 404
    assert (await attacker.get(acme.url("/monitors"))).json() == []
