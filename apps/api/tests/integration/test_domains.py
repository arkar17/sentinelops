"""DNS TXT domain verification, exceptions and renewal (OD-05, FR-MON-003, FR-PLT-009)."""

import uuid
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from sentinelops import clock
from sentinelops.catalog.domains import renew_and_expire
from sentinelops.catalog.models import DomainStatus, VerifiedDomain
from sentinelops.tenancy.models import OrgRole
from tests.integration.conftest import ClientFactory, FakeTxt, FrozenClock
from tests.integration.helpers import csrf, login, make_org, make_project, make_user, monitor_body

pytestmark = pytest.mark.integration

FQDN = "acme.example"
CHALLENGE = "_sentinelops-challenge.acme.example"


@dataclass
class Tenant:
    id: uuid.UUID
    project: uuid.UUID
    owner: httpx.AsyncClient
    member: httpx.AsyncClient
    viewer: httpx.AsyncClient

    def url(self, path: str = "") -> str:
        return f"/api/orgs/{self.id}{path}"


async def _tenant(app: FastAPI, db: AsyncSession, factory: ClientFactory, slug: str) -> Tenant:
    users = {
        role: await make_user(db, app.state.passwords, f"{role}@{slug}.test")
        for role in ("owner", "member", "viewer")
    }
    org = await make_org(
        db,
        slug=slug,
        created_by=users["owner"],
        members={
            users["owner"]: OrgRole.OWNER,
            users["member"]: OrgRole.MEMBER,
            users["viewer"]: OrgRole.VIEWER,
        },
    )
    project = await make_project(db, organization_id=org, created_by=users["owner"])
    clients = {}
    for role in users:
        clients[role] = factory()
        await login(clients[role], f"{role}@{slug}.test")
    return Tenant(org, project, clients["owner"], clients["member"], clients["viewer"])


@pytest.fixture
async def acme(app: FastAPI, db: AsyncSession, client_factory: ClientFactory) -> Tenant:
    return await _tenant(app, db, client_factory, "acme")


async def _add(tenant: Tenant, fqdn: str = FQDN) -> dict[str, Any]:
    response = await tenant.owner.post(
        tenant.url("/domains"), json={"fqdn": fqdn}, headers=csrf(tenant.owner)
    )
    assert response.status_code == 201, response.text
    return response.json()


async def test_challenge_is_org_bound_and_only_hashed(
    acme: Tenant, txt: FakeTxt, owner_engine: AsyncEngine
) -> None:
    challenge = await _add(acme, "API.Acme.Example.")
    assert challenge["record_type"] == "TXT"
    assert challenge["record_name"] == "_sentinelops-challenge.api.acme.example"
    value = str(challenge["record_value"])
    assert value.startswith("sentinelops-domain-verification=")
    async with owner_engine.connect() as conn:
        dump = str((await conn.execute(text("SELECT * FROM verified_domain"))).all())
    assert value.split("=", 1)[1] not in dump  # only the hash is stored

    domain_id = challenge["domain"]["id"]  # type: ignore[index]
    verify = acme.url(f"/domains/{domain_id}/verify")
    missing = await acme.owner.post(verify, headers=csrf(acme.owner))
    assert missing.status_code == 422
    txt.records["_sentinelops-challenge.api.acme.example"] = ["unrelated", value]
    verified = await acme.owner.post(verify, headers=csrf(acme.owner))
    assert verified.status_code == 200
    body = verified.json()
    assert body["status"] == "VERIFIED"
    assert body["expires_at"] is not None


async def test_another_org_cannot_reuse_a_proof(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory, acme: Tenant, txt: FakeTxt
) -> None:
    rival = await _tenant(app, db, client_factory, "rival")
    acme_challenge = await _add(acme)
    rival_challenge = await _add(rival)
    assert acme_challenge["record_value"] != rival_challenge["record_value"]
    txt.records[CHALLENGE] = [str(acme_challenge["record_value"])]  # only acme controls DNS

    rival_verify = rival.url(f"/domains/{rival_challenge['domain']['id']}/verify")  # type: ignore[index]
    assert (await rival.owner.post(rival_verify, headers=csrf(rival.owner))).status_code == 422
    acme_verify = acme.url(f"/domains/{acme_challenge['domain']['id']}/verify")  # type: ignore[index]
    assert (await acme.owner.post(acme_verify, headers=csrf(acme.owner))).status_code == 200
    # acme's verification does not make rival's monitors eligible
    created = await rival.owner.post(
        rival.url("/monitors"), json=monitor_body(rival.project), headers=csrf(rival.owner)
    )
    assert created.json()["lifecycle"] == "DRAFT"


async def test_challenge_expiry_and_regeneration(
    acme: Tenant, txt: FakeTxt, frozen_clock: FrozenClock
) -> None:
    challenge = await _add(acme)
    domain_id = challenge["domain"]["id"]  # type: ignore[index]
    txt.records[CHALLENGE] = [str(challenge["record_value"])]
    frozen_clock.advance(days=7, seconds=1)
    await login(acme.owner, "owner@acme.test")
    expired = await acme.owner.post(
        acme.url(f"/domains/{domain_id}/verify"), headers=csrf(acme.owner)
    )
    assert expired.status_code == 410

    fresh = await acme.owner.post(
        acme.url(f"/domains/{domain_id}/challenge"), headers=csrf(acme.owner)
    )
    assert fresh.status_code == 200
    # the old record no longer matches the new challenge
    still_old = await acme.owner.post(
        acme.url(f"/domains/{domain_id}/verify"), headers=csrf(acme.owner)
    )
    assert still_old.status_code == 422
    txt.records[CHALLENGE] = [fresh.json()["record_value"]]
    ok = await acme.owner.post(acme.url(f"/domains/{domain_id}/verify"), headers=csrf(acme.owner))
    assert ok.status_code == 200


async def test_verification_activates_waiting_monitors(acme: Tenant, txt: FakeTxt) -> None:
    created = await acme.owner.post(
        acme.url("/monitors"), json=monitor_body(acme.project), headers=csrf(acme.owner)
    )
    assert created.status_code == 201
    assert created.json()["lifecycle"] == "DRAFT"
    assert created.json()["attention_reason"] == "DOMAIN_UNVERIFIED"
    challenge = await _add(acme)
    txt.records[CHALLENGE] = [str(challenge["record_value"])]
    await acme.owner.post(
        acme.url(f"/domains/{challenge['domain']['id']}/verify"), headers=csrf(acme.owner)
    )  # type: ignore[index]
    monitor = (await acme.owner.get(acme.url(f"/monitors/{created.json()['id']}"))).json()
    assert monitor["lifecycle"] == "ACTIVE"
    assert monitor["attention_reason"] is None


async def test_parent_domain_covers_subdomains_but_not_lookalikes(
    acme: Tenant, txt: FakeTxt
) -> None:
    challenge = await _add(acme)
    txt.records[CHALLENGE] = [str(challenge["record_value"])]
    await acme.owner.post(
        acme.url(f"/domains/{challenge['domain']['id']}/verify"), headers=csrf(acme.owner)
    )  # type: ignore[index]
    for url, lifecycle in [
        ("https://api.eu.acme.example/", "ACTIVE"),
        ("https://acme.example/", "ACTIVE"),
        ("https://evilacme.example/", "DRAFT"),
        ("https://acme.example.evil.test/", "DRAFT"),
    ]:
        response = await acme.owner.post(
            acme.url("/monitors"), json=monitor_body(acme.project, url), headers=csrf(acme.owner)
        )
        assert response.json()["lifecycle"] == lifecycle, url


async def test_revocation_and_role_permissions(acme: Tenant) -> None:
    challenge = await _add(acme)
    domain_id = challenge["domain"]["id"]  # type: ignore[index]
    member_add = await acme.member.post(
        acme.url("/domains"), json={"fqdn": "x.example"}, headers=csrf(acme.member)
    )
    assert member_add.status_code == 403
    assert (await acme.member.get(acme.url("/domains"))).status_code == 200  # DOM.view
    assert (await acme.viewer.get(acme.url("/domains"))).status_code == 403
    revoked = await acme.owner.post(
        acme.url(f"/domains/{domain_id}/revoke"), headers=csrf(acme.owner)
    )
    assert revoked.json()["status"] == "REVOKED"
    again = await _add(acme)  # re-adding issues a new challenge
    assert again["domain"]["status"] == "PENDING"  # type: ignore[index]


@pytest.mark.parametrize(
    "fqdn", ["localhost", "10.0.0.1", "metadata.google.internal", "single", "a..b"]
)
async def test_unusable_domains_rejected(acme: Tenant, fqdn: str) -> None:
    response = await acme.owner.post(
        acme.url("/domains"), json={"fqdn": fqdn}, headers=csrf(acme.owner)
    )
    assert response.status_code == 422


async def test_admin_exception_flow(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory, acme: Tenant
) -> None:
    await acme.owner.post(
        acme.url("/monitors"), json=monitor_body(acme.project), headers=csrf(acme.owner)
    )
    request = await acme.owner.post(
        acme.url("/domains/exception-requests"),
        json={"fqdn": FQDN, "reason": "Fictional demo target without DNS access"},
        headers=csrf(acme.owner),
    )
    assert request.status_code == 201
    await make_user(db, app.state.passwords, "root@example.test", platform_admin=True)
    admin = client_factory()
    await login(admin, "root@example.test")
    pending = (await admin.get("/api/admin/domain-exceptions")).json()
    assert [(p["fqdn"], p["organization_slug"]) for p in pending] == [(FQDN, "acme")]
    assert (await acme.owner.get("/api/admin/domain-exceptions")).status_code == 403
    approved = await admin.post(
        f"/api/admin/domain-exceptions/{pending[0]['id']}/approve",
        json={"days": 30},
        headers=csrf(admin),
    )
    assert approved.status_code == 204
    monitors = (await acme.owner.get(acme.url("/monitors"))).json()
    assert monitors[0]["lifecycle"] == "ACTIVE"
    actions = [e["action"] for e in (await acme.owner.get(acme.url("/audit"))).json()]
    assert "platform.domain_exception_approved" in actions


async def test_renewal_extends_present_proofs_and_expires_missing_ones(
    acme: Tenant, txt: FakeTxt, db: AsyncSession, frozen_clock: FrozenClock
) -> None:
    kept = await _add(acme, "kept.example")
    lost = await _add(acme, "lost.example")
    txt.records["_sentinelops-challenge.kept.example"] = [str(kept["record_value"])]
    txt.records["_sentinelops-challenge.lost.example"] = [str(lost["record_value"])]
    for challenge in (kept, lost):
        await acme.owner.post(
            acme.url(f"/domains/{challenge['domain']['id']}/verify"), headers=csrf(acme.owner)
        )  # type: ignore[index]
    del txt.records["_sentinelops-challenge.lost.example"]

    frozen_clock.advance(days=28)  # inside the renewal window
    assert await renew_and_expire(db, txt) == (1, 0)
    frozen_clock.advance(days=3)  # lost.example's 30 days are over
    assert await renew_and_expire(db, txt) == (0, 1)
    db.expire_all()
    rows = {d.fqdn: d for d in await db.scalars(select(VerifiedDomain))}
    assert rows["kept.example"].status == DomainStatus.VERIFIED
    assert (
        rows["kept.example"].expires_at is not None
        and rows["kept.example"].expires_at > clock.now()
    )
    assert rows["lost.example"].status == DomainStatus.EXPIRED
