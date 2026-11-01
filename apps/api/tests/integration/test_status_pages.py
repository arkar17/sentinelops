"""G5 public status pages (AC-011, AC-022, AC-029, FR-UI-004, ADR-016)."""

import json
import uuid
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from sentinelops import clock
from sentinelops.platform.organizations import activate_organization, suspend_organization
from sentinelops.status_pages.routes import PublicRateLimiter
from sentinelops.status_pages.service import refresh_published
from sentinelops.tenancy.models import OrganizationLimit
from tests.integration.conftest import ClientFactory
from tests.integration.g5 import SECRET_QUERY, Tenant, tenant

pytestmark = pytest.mark.integration
__all__ = ["tenant"]

PUBLIC_KEYS = {
    "title",
    "generated_at",
    "overall",
    "components",
    "active_incidents",
    "recent_incidents",
}


@pytest.fixture
def t(tenant: Tenant) -> Tenant:
    return tenant


@pytest.fixture
def anonymous(client_factory: ClientFactory) -> httpx.AsyncClient:
    return client_factory()


async def create_page(t: Tenant, slug: str = "acme-status", **extra: Any) -> dict[str, Any]:
    body = {
        "title": "Acme service status",
        "public_slug": slug,
        "monitors": [{"monitor_id": str(t.monitor), "public_display_name": "Checkout"}],
        **extra,
    }
    response = await t.post(t.admin, "/status-pages", body)
    assert response.status_code == 201, response.text
    return response.json()


async def publish(t: Tenant, page: dict[str, Any]) -> None:
    response = await t.post(t.admin, f"/status-pages/{page['id']}/publish")
    assert response.status_code == 200 and response.json()["published"] is True


async def refresh(t: Tenant) -> None:
    async with t.session() as s:
        await refresh_published(s, clock.now())
        await s.commit()


async def test_pages_are_unpublished_until_published(
    t: Tenant, anonymous: httpx.AsyncClient
) -> None:
    page = await create_page(t)
    assert page["published"] is False
    assert (await anonymous.get("/api/status/acme-status")).status_code == 404
    await publish(t, page)
    response = await anonymous.get("/api/status/acme-status")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=30"
    body = response.json()
    assert set(body) == PUBLIC_KEYS
    assert body["components"] == [
        {"name": "Checkout", "status": "UNKNOWN", "uptime_24h": None, "uptime_7d": None}
    ]
    unpublished = await t.post(t.admin, f"/status-pages/{page['id']}/unpublish")
    assert unpublished.json()["published"] is False
    gone = await anonymous.get("/api/status/acme-status")
    assert gone.status_code == 404 and gone.headers["cache-control"] == "no-store"


async def test_public_payload_reveals_only_published_fields(
    t: Tenant, anonymous: httpx.AsyncClient
) -> None:
    page = await create_page(t)
    await publish(t, page)
    await t.check("PASS", "FAIL", "FAIL", "FAIL", tls_days=3)
    incidents = (await t.admin.get(t.url("/incidents"))).json()["items"]
    outage_id = next(i["id"] for i in incidents if i["type"] == "OUTAGE")
    await t.post(
        t.member, f"/incidents/{outage_id}/comments", {"text": "Internal: DB primary failed"}
    )
    await t.post(t.member, f"/incidents/{outage_id}/assign", {"user_id": str(t.member_id)})
    await refresh(t)
    raw = (await anonymous.get("/api/status/acme-status")).text
    body = json.loads(raw)
    assert body["overall"] == "OUTAGE"
    assert body["components"][0]["status"] == "OUTAGE"
    assert body["components"][0]["uptime_24h"] == 25.0
    assert body["active_incidents"] == [
        {
            "title": "Service disruption",
            "component": "Checkout",
            "status": "INVESTIGATING",
            "started_at": body["active_incidents"][0]["started_at"],
        }
    ]
    for private in (
        "Payments API",  # private monitor name
        "api.acme.example",
        SECRET_QUERY,
        "/health",
        "Internal: DB primary failed",
        "member@acme.test",
        "TLS",
        "HTTP_STATUS_MISMATCH",
        str(t.monitor),
        str(t.org),
    ):
        assert private not in raw, private


async def test_resolved_outages_appear_in_recent_history(
    t: Tenant, anonymous: httpx.AsyncClient
) -> None:
    page = await create_page(t)
    await publish(t, page)
    await t.check("FAIL", "FAIL", "FAIL", "PASS", "PASS")
    await refresh(t)
    body = (await anonymous.get("/api/status/acme-status")).json()
    assert body["overall"] == "OPERATIONAL"
    assert body["active_incidents"] == []
    [recent] = body["recent_incidents"]
    assert recent["title"] == "Service disruption" and recent["resolved_at"] is not None


async def test_management_changes_refresh_the_published_snapshot(
    t: Tenant, anonymous: httpx.AsyncClient
) -> None:
    page = await create_page(t)
    await publish(t, page)
    renamed = await t.patch(
        t.admin,
        f"/status-pages/{page['id']}",
        {
            "version": page["version"] + 1,
            "title": "Status",
            "monitors": [{"monitor_id": str(t.monitor), "public_display_name": "<b>API</b>"}],
        },
    )
    assert renamed.status_code == 200, renamed.text
    body = (await anonymous.get("/api/status/acme-status")).json()
    assert body["title"] == "Status"
    assert body["components"][0]["name"] == "<b>API</b>"  # stored as text; rendered escaped


async def test_status_page_limit_and_slug_rules(t: Tenant) -> None:
    for i in range(3):
        await create_page(t, slug=f"page-{i}", monitors=[])
    fourth = await t.post(
        t.admin, "/status-pages", {"title": "x", "public_slug": "page-4", "monitors": []}
    )
    assert fourth.status_code == 409 and fourth.json()["error"]["code"] == "LIMIT_EXCEEDED"
    async with t.session() as s:
        s.add(OrganizationLimit(organization_id=t.org, max_status_pages=5))
        await s.commit()
    for slug in ("-bad", "UP", "a", "has space", "x" * 41, "../admin"):
        bad = await t.post(
            t.admin, "/status-pages", {"title": "x", "public_slug": slug, "monitors": []}
        )
        assert bad.status_code == 422, slug
    taken = await t.outsider.post(
        f"/api/orgs/{t.other_org}/status-pages",
        json={"title": "x", "public_slug": "page-0", "monitors": []},
        headers={"X-CSRF-Token": t.outsider.cookies.get("sentinelops_csrf") or ""},
    )
    assert taken.status_code == 409 and taken.json()["error"]["code"] == "SLUG_TAKEN"


async def test_permissions_follow_the_matrix(t: Tenant) -> None:
    page = await create_page(t)
    pid = page["id"]
    body = {"title": "x", "public_slug": "member-page", "monitors": []}
    assert (await t.post(t.member, "/status-pages", body)).status_code == 403
    assert (await t.post(t.member, f"/status-pages/{pid}/publish")).status_code == 403
    assert (await t.patch(t.member, f"/status-pages/{pid}", {"version": 1})).status_code == 403
    for client in (t.member, t.viewer):  # STP.view: every role
        assert (await client.get(t.url("/status-pages"))).status_code == 200
        preview = await client.get(t.url(f"/status-pages/{pid}/preview"))
        assert preview.status_code == 200 and set(preview.json()) == PUBLIC_KEYS


async def test_other_organizations_cannot_manage_or_reference(t: Tenant) -> None:
    page = await create_page(t)
    other = f"/api/orgs/{t.other_org}/status-pages"
    headers = {"X-CSRF-Token": t.outsider.cookies.get("sentinelops_csrf") or ""}
    assert (await t.outsider.get(t.url("/status-pages"))).status_code == 404
    assert (await t.outsider.get(f"{other}/{page['id']}")).status_code == 404
    assert (
        await t.outsider.post(f"{other}/{page['id']}/publish", headers=headers)
    ).status_code == 404
    steal = await t.outsider.post(
        other,
        json={
            "title": "x",
            "public_slug": "globex",
            "monitors": [{"monitor_id": str(t.monitor), "public_display_name": "Stolen"}],
        },
        headers=headers,
    )
    assert steal.status_code == 404 and steal.json()["error"]["code"] == "MONITOR_NOT_FOUND"
    async with t.session() as s:
        with pytest.raises(IntegrityError):
            await s.execute(
                text(
                    "INSERT INTO status_page_monitor (organization_id, status_page_id, monitor_id, "
                    "public_display_name, sort_order) VALUES (:org, :page, :m, 'x', 0)"
                ),
                {"org": t.other_org, "page": uuid.UUID(page["id"]), "m": t.monitor},
            )


async def test_suspended_organization_page_returns_404(
    t: Tenant, anonymous: httpx.AsyncClient
) -> None:
    page = await create_page(t)
    await publish(t, page)
    async with t.session() as s:
        await suspend_organization(s, actor_id=t.admin_id, org_id=t.org, reason="review")
    assert (await anonymous.get("/api/status/acme-status")).status_code == 404
    async with t.session() as s:
        await activate_organization(s, actor_id=t.admin_id, org_id=t.org)
    assert (await anonymous.get("/api/status/acme-status")).status_code == 200


async def test_archived_monitors_and_paused_monitors_on_the_page(
    t: Tenant, anonymous: httpx.AsyncClient
) -> None:
    page = await create_page(t)
    await publish(t, page)
    await t.check("PASS")
    await refresh(t)
    assert (await anonymous.get("/api/status/acme-status")).json()["overall"] == "OPERATIONAL"
    await t.post(t.admin, f"/monitors/{t.monitor}/pause")
    await refresh(t)
    paused = (await anonymous.get("/api/status/acme-status")).json()
    assert paused["components"][0]["status"] == "UNKNOWN"
    await t.post(t.admin, f"/monitors/{t.monitor}/archive")
    await refresh(t)
    archived = (await anonymous.get("/api/status/acme-status")).json()
    assert archived["components"] == []


async def test_public_endpoint_is_rate_limited(t: Tenant, anonymous: httpx.AsyncClient) -> None:
    page = await create_page(t)
    await publish(t, page)
    t.app.state.public_rate_limiter = PublicRateLimiter(limit=3)
    codes = [(await anonymous.get("/api/status/acme-status")).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert (await anonymous.get("/api/status/no-such-page")).status_code == 429
