"""Cross-organization isolation and the role-by-action matrix over HTTP (G2, AC-001/021/025/029)."""

import uuid
from dataclasses import dataclass

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.authz.matrix import allows
from sentinelops.catalog.models import Project
from sentinelops.tenancy.models import OrgRole, UserPreference
from tests.integration.conftest import ClientFactory
from tests.integration.helpers import csrf, login, make_org, make_user

pytestmark = pytest.mark.integration


@dataclass
class Tenants:
    org_a: uuid.UUID
    org_b: uuid.UUID
    owner_a: httpx.AsyncClient
    owner_b: httpx.AsyncClient
    project_b: str
    member_b: uuid.UUID
    invitation_b: str


@pytest.fixture
async def tenants(app: FastAPI, db: AsyncSession, client_factory: ClientFactory) -> Tenants:
    alice = await make_user(db, app.state.passwords, "alice@a.test")
    bob = await make_user(db, app.state.passwords, "bob@b.test")
    carol = await make_user(db, app.state.passwords, "carol@b.test")
    org_a = await make_org(db, slug="org-a", created_by=alice, members={alice: OrgRole.OWNER})
    org_b = await make_org(
        db, slug="org-b", created_by=bob, members={bob: OrgRole.OWNER, carol: OrgRole.VIEWER}
    )
    owner_a, owner_b = client_factory(), client_factory()
    await login(owner_a, "alice@a.test")
    await login(owner_b, "bob@b.test")
    project = await owner_b.post(
        f"/api/orgs/{org_b}/projects", json={"name": "B-only"}, headers=csrf(owner_b)
    )
    invitation = await owner_b.post(
        f"/api/orgs/{org_b}/invitations",
        json={"email": "dave@b.test", "role": "VIEWER"},
        headers=csrf(owner_b),
    )
    return Tenants(
        org_a, org_b, owner_a, owner_b, project.json()["id"], carol, invitation.json()["id"]
    )


def _org_routes(
    org: uuid.UUID, project: str, member: uuid.UUID, invitation: str
) -> list[tuple[str, str, dict[str, object] | None]]:
    base = f"/api/orgs/{org}"
    return [
        ("GET", base, None),
        ("PATCH", base, {"version": 1, "name": "X"}),
        ("GET", f"{base}/members", None),
        ("GET", f"{base}/invitations", None),
        ("POST", f"{base}/invitations", {"email": "x@example.test", "role": "VIEWER"}),
        ("DELETE", f"{base}/invitations/{invitation}", None),
        ("PUT", f"{base}/members/{member}/role", {"role": "ORG_MEMBER"}),
        ("PUT", f"{base}/members/{member}/status", {"status": "SUSPENDED"}),
        ("DELETE", f"{base}/members/{member}", None),
        ("POST", f"{base}/leave", None),
        ("GET", f"{base}/audit", None),
        ("GET", f"{base}/projects", None),
        ("POST", f"{base}/projects", {"name": "Injected"}),
        ("PATCH", f"{base}/projects/{project}", {"version": 1, "name": "Y"}),
        ("POST", f"{base}/projects/{project}/archive", None),
        ("POST", f"{base}/projects/{project}/unarchive", None),
    ]


async def test_other_organizations_are_invisible(tenants: Tenants) -> None:
    """Owner of A, on every route of B, gets 404 and B is unchanged."""
    client = tenants.owner_a
    for method, path, body in _org_routes(
        tenants.org_b, tenants.project_b, tenants.member_b, tenants.invitation_b
    ):
        response = await client.request(method, path, json=body, headers=csrf(client))
        assert response.status_code == 404, (method, path, response.status_code)
        assert "B-only" not in response.text
    projects = (await tenants.owner_b.get(f"/api/orgs/{tenants.org_b}/projects")).json()
    assert [p["name"] for p in projects] == ["B-only"]
    assert len((await tenants.owner_b.get(f"/api/orgs/{tenants.org_b}/members")).json()) == 2


async def test_foreign_ids_inside_own_organization_are_not_found(tenants: Tenants) -> None:
    """Owner of A, using B's entity IDs under A's own path, gets 404 (IDs never imply an org)."""
    client = tenants.owner_a
    base = f"/api/orgs/{tenants.org_a}"
    for method, path, body in [
        ("PATCH", f"{base}/projects/{tenants.project_b}", {"version": 1, "name": "Hijack"}),
        ("POST", f"{base}/projects/{tenants.project_b}/archive", None),
        ("PUT", f"{base}/members/{tenants.member_b}/role", {"role": "ORG_ADMIN"}),
        ("PUT", f"{base}/members/{tenants.member_b}/status", {"status": "SUSPENDED"}),
        ("DELETE", f"{base}/members/{tenants.member_b}", None),
        ("DELETE", f"{base}/invitations/{tenants.invitation_b}", None),
    ]:
        response = await client.request(method, path, json=body, headers=csrf(client))
        assert response.status_code == 404, (method, path)


async def test_audit_logs_are_tenant_scoped(tenants: Tenants) -> None:
    a_events = (await tenants.owner_a.get(f"/api/orgs/{tenants.org_a}/audit")).json()
    b_events = (await tenants.owner_b.get(f"/api/orgs/{tenants.org_b}/audit")).json()
    assert a_events == []
    assert {e["action"] for e in b_events} == {"org.project_created", "org.member_invited"}


async def test_system_admin_without_membership_gets_404(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory, tenants: Tenants
) -> None:
    await make_user(db, app.state.passwords, "root@example.test", platform_admin=True)
    admin = client_factory()
    await login(admin, "root@example.test")
    for method, path, body in _org_routes(
        tenants.org_b, tenants.project_b, tenants.member_b, tenants.invitation_b
    ):
        response = await admin.request(method, path, json=body, headers=csrf(admin))
        assert response.status_code == 404, (method, path)


async def test_preference_cannot_point_at_a_foreign_organization(
    db: AsyncSession, tenants: Tenants
) -> None:
    alice_id = uuid.UUID((await tenants.owner_a.get("/api/auth/me")).json()["id"])
    db.add(UserPreference(user_id=alice_id, selected_org_id=tenants.org_b, updated_at=clock.now()))
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


async def test_project_names_unique_only_within_an_organization(tenants: Tenants) -> None:
    same = await tenants.owner_a.post(
        f"/api/orgs/{tenants.org_a}/projects",
        json={"name": "b-only"},
        headers=csrf(tenants.owner_a),
    )
    assert same.status_code == 201  # same name in another org is fine
    dup = await tenants.owner_b.post(
        f"/api/orgs/{tenants.org_b}/projects",
        json={"name": "B-ONLY"},
        headers=csrf(tenants.owner_b),
    )
    assert dup.status_code == 409


async def test_project_cannot_be_created_for_another_org_via_body(
    db: AsyncSession, tenants: Tenants
) -> None:
    """organization_id in a request body is ignored; the path context decides."""
    response = await tenants.owner_a.post(
        f"/api/orgs/{tenants.org_a}/projects",
        json={"name": "Sneaky", "organization_id": str(tenants.org_b)},
        headers=csrf(tenants.owner_a),
    )
    assert response.status_code == 201
    project = await db.get(Project, uuid.UUID(response.json()["id"]))
    assert project is not None
    assert project.organization_id == tenants.org_a


# --- role-by-action matrix over HTTP ---------------------------------------------------------

ROLE_EMAILS = {
    OrgRole.OWNER: "o@m.test",
    OrgRole.ADMIN: "a@m.test",
    OrgRole.MEMBER: "m@m.test",
    OrgRole.VIEWER: "v@m.test",
}


@pytest.mark.parametrize("role", sorted(ROLE_EMAILS))
async def test_http_permissions_follow_the_matrix(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory, role: str
) -> None:
    ids = {r: await make_user(db, app.state.passwords, e) for r, e in ROLE_EMAILS.items()}
    target = await make_user(db, app.state.passwords, "target@m.test")
    org = await make_org(
        db,
        slug="matrix",
        created_by=ids[OrgRole.OWNER],
        members={**{ids[r]: r for r in ROLE_EMAILS}, target: OrgRole.VIEWER},
    )
    client = client_factory()
    await login(client, ROLE_EMAILS[role])
    base = f"/api/orgs/{org}"
    matrix_project = Project(
        organization_id=org,
        name="Matrix project",
        created_by=ids[OrgRole.OWNER],
        created_at=clock.now(),
        updated_at=clock.now(),
    )
    db.add(matrix_project)
    await db.commit()
    project = matrix_project.id
    cases = [
        ("ORG.view", "GET", base, None),
        ("ORG.update", "PATCH", base, {"version": 1}),
        ("ORG.audit.view", "GET", f"{base}/audit", None),
        ("MEM.list", "GET", f"{base}/members", None),
        ("MEM.invite", "POST", f"{base}/invitations", {"email": "n@m.test", "role": "VIEWER"}),
        ("MEM.role.change", "PUT", f"{base}/members/{target}/role", {"role": "ORG_MEMBER"}),
        ("MEM.status.change", "PUT", f"{base}/members/{target}/status", {"status": "ACTIVE"}),
        ("PRJ.view", "GET", f"{base}/projects", None),
        ("PRJ.create", "POST", f"{base}/projects", {"name": f"By {role}"}),
        ("PRJ.update", "PATCH", f"{base}/projects/{project}", {"version": 1, "description": "d"}),
        ("PRJ.archive", "POST", f"{base}/projects/{project}/unarchive", None),
    ]
    for action, method, path, body in cases:
        response = await client.request(method, path, json=body, headers=csrf(client))
        if allows(role, action):
            assert response.status_code < 400, (role, action, response.text)
        else:
            assert response.status_code == 403, (role, action, response.status_code)
            assert response.json()["error"]["code"] == "FORBIDDEN"
