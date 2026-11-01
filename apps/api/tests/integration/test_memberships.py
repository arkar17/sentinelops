"""Multi-organization memberships, switching, revocation, invitations and role rules (G2)."""

import asyncio
import uuid
from dataclasses import dataclass

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.tenancy.models import MemberStatus, OrganizationMember, OrgRole
from tests.integration.conftest import ClientFactory, FrozenClock, RecordingMailer
from tests.integration.helpers import (
    PASSWORD,
    csrf,
    login,
    make_org,
    make_user,
    token_from_link,
)

pytestmark = pytest.mark.integration


@dataclass
class Org:
    id: uuid.UUID
    clients: dict[str, httpx.AsyncClient]
    users: dict[str, uuid.UUID]

    def url(self, path: str = "") -> str:
        return f"/api/orgs/{self.id}{path}"


@pytest.fixture
async def org(app: FastAPI, db: AsyncSession, client_factory: ClientFactory) -> Org:
    """One fictional organization with a member of every role (each with its own browser)."""
    roles = {
        "owner": OrgRole.OWNER,
        "admin": OrgRole.ADMIN,
        "member": OrgRole.MEMBER,
        "viewer": OrgRole.VIEWER,
    }
    users = {name: await make_user(db, app.state.passwords, f"{name}@acme.test") for name in roles}
    org_id = await make_org(
        db, slug="acme", created_by=users["owner"], members={users[n]: r for n, r in roles.items()}
    )
    clients: dict[str, httpx.AsyncClient] = {}
    for name in roles:
        clients[name] = client_factory()
        assert (await login(clients[name], f"{name}@acme.test")).status_code == 200
    return Org(org_id, clients, users)


async def _invite(client: httpx.AsyncClient, org: Org, email: str, role: str) -> httpx.Response:
    return await client.post(
        org.url("/invitations"), json={"email": email, "role": role}, headers=csrf(client)
    )


# --- multiple organizations and switching ---------------------------------------------------------


async def test_one_user_with_independent_roles_in_two_orgs(
    app: FastAPI, db: AsyncSession, client: httpx.AsyncClient
) -> None:
    user = await make_user(db, app.state.passwords, "dual@example.test")
    org_a = await make_org(db, slug="alpha", created_by=user, members={user: OrgRole.VIEWER})
    org_b = await make_org(db, slug="beta", created_by=user, members={user: OrgRole.ADMIN})
    await login(client, "dual@example.test")

    listing = (await client.get("/api/me/organizations")).json()
    assert {(o["slug"], o["role"]) for o in listing["organizations"]} == {
        ("alpha", "VIEWER"),
        ("beta", "ORG_ADMIN"),
    }
    create = {"name": "Payments"}
    denied = await client.post(f"/api/orgs/{org_a}/projects", json=create, headers=csrf(client))
    assert denied.status_code == 403
    allowed = await client.post(f"/api/orgs/{org_b}/projects", json=create, headers=csrf(client))
    assert allowed.status_code == 201
    assert (await client.get(f"/api/orgs/{org_a}/projects")).json() == []


async def test_switching_validates_membership_and_ignores_stale_selection(org: Org) -> None:
    member = org.clients["member"]
    ok = await member.put(
        "/api/me/preferences", json={"selected_org_id": str(org.id)}, headers=csrf(member)
    )
    assert ok.status_code == 204
    assert (await member.get("/api/me/organizations")).json()["selected_org_id"] == str(org.id)

    foreign = await member.put(
        "/api/me/preferences", json={"selected_org_id": str(uuid.uuid4())}, headers=csrf(member)
    )
    assert foreign.status_code == 404

    owner = org.clients["owner"]
    await owner.delete(org.url(f"/members/{org.users['member']}"), headers=csrf(owner))
    after = (await member.get("/api/me/organizations")).json()
    assert after == {"organizations": [], "selected_org_id": None}


async def test_revocation_takes_effect_on_the_next_request(org: Org) -> None:
    member, owner = org.clients["member"], org.clients["owner"]
    assert (await member.get(org.url())).status_code == 200
    removed = await owner.delete(org.url(f"/members/{org.users['member']}"), headers=csrf(owner))
    assert removed.status_code == 204
    assert (await member.get(org.url())).status_code == 404  # same session, no re-login
    assert (await member.get("/api/auth/me")).status_code == 200  # global account unaffected


async def test_suspended_membership_is_treated_as_non_member(org: Org) -> None:
    viewer, admin = org.clients["viewer"], org.clients["admin"]
    path = org.url(f"/members/{org.users['viewer']}/status")
    assert (
        await admin.put(path, json={"status": "SUSPENDED"}, headers=csrf(admin))
    ).status_code == 204
    assert (await viewer.get(org.url())).status_code == 404
    assert (
        await admin.put(path, json={"status": "ACTIVE"}, headers=csrf(admin))
    ).status_code == 204
    assert (await viewer.get(org.url())).status_code == 200


# --- invitations ----------------------------------------------------------------------------------


async def test_invitation_for_new_user(
    org: Org, client_factory: ClientFactory, mailer: RecordingMailer
) -> None:
    response = await _invite(org.clients["admin"], org, "Newbie@Example.test", "ORG_MEMBER")
    assert response.status_code == 201
    assert "token" not in response.text
    token = token_from_link(mailer.messages[-1].body)
    newcomer = client_factory()
    preview = await newcomer.post("/api/auth/org-invitations/preview", json={"token": token})
    assert preview.json() == {
        "organization_name": "Acme",
        "role": "ORG_MEMBER",
        "email": "newbie@example.test",
        "account_exists": False,
    }
    accepted = await newcomer.post(
        "/api/auth/org-invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert accepted.json() == {"organization_id": str(org.id)}
    await login(newcomer, "newbie@example.test")
    assert (await newcomer.get(org.url())).json()["my_role"] == "ORG_MEMBER"

    replay = await client_factory().post(
        "/api/auth/org-invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert replay.status_code == 400


async def test_invitation_expiry_and_revocation(
    org: Org, client_factory: ClientFactory, mailer: RecordingMailer, frozen_clock: FrozenClock
) -> None:
    owner = org.clients["owner"]
    first = await _invite(owner, org, "late@example.test", "VIEWER")
    token = token_from_link(mailer.messages[-1].body)
    revoke = await owner.delete(org.url(f"/invitations/{first.json()['id']}"), headers=csrf(owner))
    assert revoke.status_code == 204
    body = {"token": token, "password": PASSWORD}
    assert (
        await client_factory().post("/api/auth/org-invitations/accept", json=body)
    ).status_code == 400

    await _invite(owner, org, "late@example.test", "VIEWER")
    token = token_from_link(mailer.messages[-1].body)
    frozen_clock.advance(days=7, seconds=1)
    body = {"token": token, "password": PASSWORD}
    assert (
        await client_factory().post("/api/auth/org-invitations/accept", json=body)
    ).status_code == 400


async def test_existing_account_must_be_signed_in_as_invitee(
    org: Org,
    app: FastAPI,
    db: AsyncSession,
    client_factory: ClientFactory,
    mailer: RecordingMailer,
) -> None:
    await make_user(db, app.state.passwords, "existing@example.test")
    await _invite(org.clients["owner"], org, "existing@example.test", "VIEWER")
    token = token_from_link(mailer.messages[-1].body)

    anonymous = await client_factory().post(
        "/api/auth/org-invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert anonymous.status_code == 401
    other = org.clients["member"]
    wrong = await other.post(
        "/api/auth/org-invitations/accept", json={"token": token}, headers=csrf(other)
    )
    assert wrong.status_code == 401

    invitee = client_factory()
    await login(invitee, "existing@example.test")
    accepted = await invitee.post(
        "/api/auth/org-invitations/accept", json={"token": token}, headers=csrf(invitee)
    )
    assert accepted.status_code == 200
    assert (await invitee.get(org.url())).json()["my_role"] == "VIEWER"


@pytest.mark.parametrize(
    ("inviter", "role", "expected"),
    [
        ("owner", "ORG_OWNER", 201),
        ("owner", "ORG_ADMIN", 201),
        ("admin", "ORG_MEMBER", 201),
        ("admin", "VIEWER", 201),
        ("admin", "ORG_ADMIN", 403),
        ("admin", "ORG_OWNER", 403),
        ("member", "VIEWER", 403),
        ("viewer", "VIEWER", 403),
    ],
)
async def test_invitation_role_rules(org: Org, inviter: str, role: str, expected: int) -> None:
    response = await _invite(org.clients[inviter], org, "candidate@example.test", role)
    assert response.status_code == expected


async def test_inviting_an_active_member_conflicts(org: Org) -> None:
    response = await _invite(org.clients["owner"], org, "viewer@acme.test", "ORG_ADMIN")
    assert response.status_code == 409


async def test_removed_member_can_be_reinvited(org: Org, mailer: RecordingMailer) -> None:
    owner, viewer = org.clients["owner"], org.clients["viewer"]
    await owner.delete(org.url(f"/members/{org.users['viewer']}"), headers=csrf(owner))
    assert (await _invite(owner, org, "viewer@acme.test", "ORG_MEMBER")).status_code == 201
    token = token_from_link(mailer.messages[-1].body)
    accepted = await viewer.post(
        "/api/auth/org-invitations/accept", json={"token": token}, headers=csrf(viewer)
    )
    assert accepted.status_code == 200
    assert (await viewer.get(org.url())).json()["my_role"] == "ORG_MEMBER"


# --- role and membership rules --------------------------------------------------------------------


async def _set_role(client: httpx.AsyncClient, org: Org, user: str, role: str) -> httpx.Response:
    return await client.put(
        org.url(f"/members/{org.users[user]}/role"), json={"role": role}, headers=csrf(client)
    )


@pytest.mark.parametrize(
    ("actor", "target", "role", "expected"),
    [
        ("owner", "member", "ORG_ADMIN", 204),
        ("owner", "admin", "VIEWER", 204),
        ("owner", "viewer", "ORG_OWNER", 204),
        ("admin", "member", "VIEWER", 204),
        ("admin", "viewer", "ORG_MEMBER", 204),
        ("admin", "member", "ORG_ADMIN", 403),
        ("admin", "owner", "VIEWER", 403),
        ("member", "viewer", "ORG_MEMBER", 403),
        ("viewer", "member", "VIEWER", 403),
        ("admin", "admin", "ORG_OWNER", 403),
        ("member", "member", "ORG_OWNER", 403),
    ],
)
async def test_role_change_rules(
    org: Org, actor: str, target: str, role: str, expected: int
) -> None:
    assert (await _set_role(org.clients[actor], org, target, role)).status_code == expected


async def test_last_owner_cannot_demote_leave_or_be_removed(org: Org) -> None:
    owner = org.clients["owner"]
    demote = await _set_role(owner, org, "owner", "ORG_ADMIN")
    assert demote.status_code == 409
    assert demote.json()["error"]["code"] == "LAST_OWNER"
    assert (await owner.post(org.url("/leave"), headers=csrf(owner))).status_code == 409


async def test_owner_may_step_down_when_another_owner_exists(org: Org) -> None:
    owner = org.clients["owner"]
    assert (await _set_role(owner, org, "admin", "ORG_OWNER")).status_code == 204
    assert (await _set_role(owner, org, "owner", "ORG_ADMIN")).status_code == 204
    assert (await owner.get(org.url())).json()["my_role"] == "ORG_ADMIN"


async def test_admin_cannot_remove_or_suspend_owners_or_admins(org: Org) -> None:
    admin = org.clients["admin"]
    owner_path = org.url(f"/members/{org.users['owner']}")
    assert (await admin.delete(owner_path, headers=csrf(admin))).status_code == 403
    assert (
        await admin.put(f"{owner_path}/status", json={"status": "SUSPENDED"}, headers=csrf(admin))
    ).status_code == 403


async def test_member_may_leave(org: Org) -> None:
    member = org.clients["member"]
    assert (await member.post(org.url("/leave"), headers=csrf(member))).status_code == 204
    assert (await member.get(org.url())).status_code == 404


async def test_concurrent_mutual_demotion_keeps_an_owner(org: Org, db: AsyncSession) -> None:
    owner = org.clients["owner"]
    assert (await _set_role(owner, org, "admin", "ORG_OWNER")).status_code == 204
    second = org.clients["admin"]  # now an owner too
    results = await asyncio.gather(
        _set_role(owner, org, "admin", "ORG_ADMIN"),
        _set_role(second, org, "owner", "ORG_ADMIN"),
    )
    assert sorted(r.status_code for r in results) == [204, 403]
    owners = await db.scalar(
        select(func.count())
        .select_from(OrganizationMember)
        .where(
            OrganizationMember.organization_id == org.id,
            OrganizationMember.role == OrgRole.OWNER,
            OrganizationMember.status == MemberStatus.ACTIVE,
        )
    )
    assert owners == 1


async def test_concurrent_mutual_removal_keeps_an_owner(org: Org, db: AsyncSession) -> None:
    owner = org.clients["owner"]
    await _set_role(owner, org, "admin", "ORG_OWNER")
    second = org.clients["admin"]
    results = await asyncio.gather(
        owner.delete(org.url(f"/members/{org.users['admin']}"), headers=csrf(owner)),
        second.delete(org.url(f"/members/{org.users['owner']}"), headers=csrf(second)),
    )
    assert sorted(r.status_code for r in results) == [204, 404]
    owners = await db.scalar(
        select(func.count())
        .select_from(OrganizationMember)
        .where(
            OrganizationMember.organization_id == org.id,
            OrganizationMember.role == OrgRole.OWNER,
            OrganizationMember.status == MemberStatus.ACTIVE,
        )
    )
    assert owners == 1


async def test_profile_update_owner_only(org: Org) -> None:
    owner, admin = org.clients["owner"], org.clients["admin"]
    profile = (await owner.get(org.url())).json()
    body = {"version": profile["version"], "name": "Acme Labs", "timezone": "Asia/Tokyo"}
    assert (await admin.patch(org.url(), json=body, headers=csrf(admin))).status_code == 403
    updated = await owner.patch(org.url(), json=body, headers=csrf(owner))
    assert updated.status_code == 200
    assert updated.json()["timezone"] == "Asia/Tokyo"
    bad = {"version": updated.json()["version"], "timezone": "Nowhere/Land"}
    assert (await owner.patch(org.url(), json=bad, headers=csrf(owner))).status_code == 422


async def test_org_audit_records_member_events_for_owners_and_admins(org: Org) -> None:
    owner = org.clients["owner"]
    await _set_role(owner, org, "member", "VIEWER")
    events = (await owner.get(org.url("/audit"))).json()
    change = next(e for e in events if e["action"] == "org.member_role_changed")
    assert change["details"] == {"from": "ORG_MEMBER", "to": "VIEWER"}
    assert change["scope"] == "ORGANIZATION"
    assert change["actor_email"] == "owner@acme.test"
    assert (await org.clients["admin"].get(org.url("/audit"))).status_code == 200
    assert (await org.clients["member"].get(org.url("/audit"))).status_code == 403
