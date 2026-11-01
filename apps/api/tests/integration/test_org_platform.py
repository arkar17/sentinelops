"""SYSTEM_ADMIN organization lifecycle and metadata-only visibility (G2, FR-PLT-003…008)."""

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.tenancy.models import OrganizationMember
from tests.integration.conftest import ClientFactory, FrozenClock, RecordingMailer
from tests.integration.helpers import PASSWORD, csrf, login, make_user, token_from_link

pytestmark = pytest.mark.integration

ADMIN = "root@example.test"
OWNER = "owner@acme.example.test"


@pytest.fixture
async def admin(app: FastAPI, db: AsyncSession, client: httpx.AsyncClient) -> httpx.AsyncClient:
    await make_user(db, app.state.passwords, ADMIN, platform_admin=True)
    assert (await login(client, ADMIN)).status_code == 200
    return client


async def _create(
    admin: httpx.AsyncClient, slug: str = "acme", owner: str = OWNER
) -> httpx.Response:
    return await admin.post(
        "/api/admin/organizations",
        json={
            "name": "Acme (fictional)",
            "slug": slug,
            "timezone": "Europe/Berlin",
            "owner_email": owner,
        },
        headers=csrf(admin),
    )


async def _accept_owner(
    client_factory: ClientFactory, mailer: RecordingMailer, email: str = OWNER
) -> httpx.AsyncClient:
    token = token_from_link(mailer.messages[-1].body)
    owner = client_factory()
    accepted = await owner.post(
        "/api/auth/org-invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert accepted.status_code == 200, accepted.text
    assert (await login(owner, email)).status_code == 200
    return owner


async def test_create_org_provisions_owner_without_admin_membership(
    admin: httpx.AsyncClient,
    client_factory: ClientFactory,
    mailer: RecordingMailer,
    db: AsyncSession,
) -> None:
    response = await _create(admin)
    assert response.status_code == 201
    meta = response.json()
    assert meta["status"] == "ACTIVE"
    assert meta["owner_emails"] == []
    assert meta["pending_owner_invitation"] is True
    assert [m.to for m in mailer.messages] == [OWNER]
    org_id = meta["id"]

    # The creating SYSTEM_ADMIN is not a member and cannot see organization routes.
    assert await db.scalar(select(func.count()).select_from(OrganizationMember)) == 0
    assert (await admin.get(f"/api/orgs/{org_id}")).status_code == 404
    assert (await admin.get("/api/me/organizations")).json()["organizations"] == []

    owner = await _accept_owner(client_factory, mailer)
    profile = (await owner.get(f"/api/orgs/{org_id}")).json()
    assert profile["my_role"] == "ORG_OWNER"
    assert profile["timezone"] == "Europe/Berlin"
    after = (await admin.get(f"/api/admin/organizations/{org_id}")).json()
    assert after["owner_emails"] == [OWNER]
    assert after["pending_owner_invitation"] is False


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({"slug": "Bad Slug"}, "INVALID_SLUG"),
        ({"slug": "-edge"}, "INVALID_SLUG"),
        ({"timezone": "Mars/Olympus"}, "INVALID_TIMEZONE"),
        ({"owner_email": "not-an-email"}, "INVALID_EMAIL"),
    ],
)
async def test_create_org_validation(
    admin: httpx.AsyncClient, payload: dict[str, str], code: str
) -> None:
    body = {"name": "X", "slug": "valid-slug", "timezone": "UTC", "owner_email": OWNER, **payload}
    response = await admin.post("/api/admin/organizations", json=body, headers=csrf(admin))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == code


async def test_duplicate_slug_conflicts(admin: httpx.AsyncClient) -> None:
    assert (await _create(admin)).status_code == 201
    response = await _create(admin, owner="other@example.test")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "SLUG_TAKEN"


async def test_ordinary_users_cannot_create_organizations(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory
) -> None:
    await make_user(db, app.state.passwords, "someone@example.test")
    user = client_factory()
    await login(user, "someone@example.test")
    body = {
        "name": "Mine",
        "slug": "mine",
        "timezone": "UTC",
        "owner_email": "someone@example.test",
    }
    assert (
        await user.post("/api/admin/organizations", json=body, headers=csrf(user))
    ).status_code == 403
    # There is no organization self-signup route at all.
    assert (await user.post("/api/orgs", json=body, headers=csrf(user))).status_code in (404, 405)


async def test_metadata_excludes_private_organization_data(
    admin: httpx.AsyncClient, client_factory: ClientFactory, mailer: RecordingMailer
) -> None:
    org_id = (await _create(admin)).json()["id"]
    owner = await _accept_owner(client_factory, mailer)
    await owner.post(
        f"/api/orgs/{org_id}/projects", json={"name": "Secret Project X"}, headers=csrf(owner)
    )
    await owner.post(
        f"/api/orgs/{org_id}/invitations",
        json={"email": "quiet.viewer@example.test", "role": "VIEWER"},
        headers=csrf(owner),
    )
    token = token_from_link(mailer.messages[-1].body)
    await client_factory().post(
        "/api/auth/org-invitations/accept", json={"token": token, "password": PASSWORD}
    )
    for path in ("/api/admin/organizations", f"/api/admin/organizations/{org_id}"):
        response = await admin.get(path)
        assert response.status_code == 200
        assert "Secret Project X" not in response.text
        assert "quiet.viewer@example.test" not in response.text
    meta = (await admin.get(f"/api/admin/organizations/{org_id}")).json()
    assert meta["member_count"] == 2
    assert meta["project_count"] == 1


async def test_suspension_blocks_members_and_activation_restores(
    admin: httpx.AsyncClient,
    client_factory: ClientFactory,
    mailer: RecordingMailer,
    app: FastAPI,
    db: AsyncSession,
) -> None:
    org_id = (await _create(admin)).json()["id"]
    owner = await _accept_owner(client_factory, mailer)
    await make_user(db, app.state.passwords, "outsider@example.test")
    outsider = client_factory()
    await login(outsider, "outsider@example.test")

    suspended = await admin.post(
        f"/api/admin/organizations/{org_id}/suspend",
        json={"reason": "Fictional abuse report"},
        headers=csrf(admin),
    )
    assert suspended.json()["status"] == "SUSPENDED"
    for path in ("", "/members", "/projects", "/audit"):
        response = await owner.get(f"/api/orgs/{org_id}{path}")
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "ORG_SUSPENDED"
    write = await owner.post(
        f"/api/orgs/{org_id}/projects", json={"name": "P"}, headers=csrf(owner)
    )
    assert write.status_code == 403
    assert (await outsider.get(f"/api/orgs/{org_id}")).status_code == 404  # still non-disclosing
    listing = (await owner.get("/api/me/organizations")).json()["organizations"]
    assert listing[0]["organization_status"] == "SUSPENDED"

    activated = await admin.post(f"/api/admin/organizations/{org_id}/activate", headers=csrf(admin))
    assert activated.json()["status"] == "ACTIVE"
    assert (await owner.get(f"/api/orgs/{org_id}")).status_code == 200
    actions = [e["action"] for e in (await owner.get(f"/api/orgs/{org_id}/audit")).json()]
    assert "platform.org_suspended" in actions
    assert "platform.org_activated" in actions


async def test_suspended_org_invitations_cannot_be_accepted(
    admin: httpx.AsyncClient, client_factory: ClientFactory, mailer: RecordingMailer
) -> None:
    org_id = (await _create(admin)).json()["id"]
    await admin.post(
        f"/api/admin/organizations/{org_id}/suspend",
        json={"reason": "Pending review"},
        headers=csrf(admin),
    )
    token = token_from_link(mailer.messages[-1].body)
    response = await client_factory().post(
        "/api/auth/org-invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert response.status_code == 403


async def test_limits_override_and_reset(
    admin: httpx.AsyncClient, client_factory: ClientFactory, mailer: RecordingMailer
) -> None:
    org_id = (await _create(admin)).json()["id"]
    owner = await _accept_owner(client_factory, mailer)
    body = {
        "max_monitors": 50,
        "min_interval_seconds": 120,
        "max_status_pages": None,
        "max_channels": 2,
    }
    updated = await admin.put(
        f"/api/admin/organizations/{org_id}/limits", json=body, headers=csrf(admin)
    )
    assert updated.status_code == 200
    limits = (await owner.get(f"/api/orgs/{org_id}")).json()["limits"]
    assert limits == {
        "max_monitors": 50,
        "min_interval_seconds": 120,
        "max_status_pages": 3,
        "max_channels": 2,
    }

    reset = {
        "max_monitors": None,
        "min_interval_seconds": None,
        "max_status_pages": None,
        "max_channels": None,
    }
    await admin.put(f"/api/admin/organizations/{org_id}/limits", json=reset, headers=csrf(admin))
    assert (await owner.get(f"/api/orgs/{org_id}")).json()["limits"]["max_monitors"] == 20

    for bad in ({**reset, "min_interval_seconds": 90}, {**reset, "max_monitors": 0}):
        response = await admin.put(
            f"/api/admin/organizations/{org_id}/limits", json=bad, headers=csrf(admin)
        )
        assert response.status_code == 422


async def test_owner_invite_only_when_no_active_owner(
    admin: httpx.AsyncClient,
    client_factory: ClientFactory,
    mailer: RecordingMailer,
    frozen_clock: FrozenClock,
) -> None:
    org_id = (await _create(admin)).json()["id"]
    frozen_clock.advance(days=7, seconds=1)  # the first owner invitation expired unused
    await login(admin, ADMIN)  # fresh session after the time jump
    reissued = await admin.post(
        f"/api/admin/organizations/{org_id}/owner-invitations",
        json={"email": "new.owner@example.test"},
        headers=csrf(admin),
    )
    assert reissued.status_code == 201
    await _accept_owner(client_factory, mailer, "new.owner@example.test")

    # With an active owner, a SYSTEM_ADMIN cannot issue itself an owner invitation.
    self_grant = await admin.post(
        f"/api/admin/organizations/{org_id}/owner-invitations",
        json={"email": ADMIN},
        headers=csrf(admin),
    )
    assert self_grant.status_code == 409
    assert self_grant.json()["error"]["code"] == "ORGANIZATION_HAS_OWNER"


async def test_platform_org_update_and_dashboard(admin: httpx.AsyncClient) -> None:
    meta = (await _create(admin)).json()
    patched = await admin.patch(
        f"/api/admin/organizations/{meta['id']}",
        json={"version": meta["version"], "name": "Acme Renamed", "slug": "acme-renamed"},
        headers=csrf(admin),
    )
    assert patched.status_code == 200
    assert patched.json()["slug"] == "acme-renamed"
    stale = await admin.patch(
        f"/api/admin/organizations/{meta['id']}",
        json={"version": meta["version"], "name": "Again"},
        headers=csrf(admin),
    )
    assert stale.status_code == 409
    await admin.post(
        f"/api/admin/organizations/{meta['id']}/suspend",
        json={"reason": "Testing"},
        headers=csrf(admin),
    )
    dashboard = (await admin.get("/api/admin/dashboard")).json()
    assert dashboard["organizations_by_status"] == {"ACTIVE": 0, "SUSPENDED": 1}
