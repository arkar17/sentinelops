"""SYSTEM_ADMIN MFA (OD-01): enrolment, login verification, replay, recovery codes, policy
enforcement, session revocation and operator reset; trusted-proxy throttling."""

import json
import uuid
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.models import AuditEvent
from sentinelops.identity import mfa
from sentinelops.identity.mfa_service import operator_reset
from sentinelops.identity.models import AdminMfa
from sentinelops.tenancy.models import OrgRole
from tests.integration.conftest import ClientFactory, FrozenClock
from tests.integration.helpers import PASSWORD, csrf, login, make_org, make_user

pytestmark = pytest.mark.integration
EMAIL = "root@platform.test"


def code(secret: str, offset_steps: int = 0) -> str:
    return mfa.code_at(secret, mfa.step_of(clock.now()) + offset_steps)


async def post(client: httpx.AsyncClient, path: str, body: Any = None) -> httpx.Response:
    return await client.post(path, json=body, headers=csrf(client))


async def enroll(client: httpx.AsyncClient, clk: FrozenClock) -> tuple[str, list[str]]:
    started = await post(client, "/api/auth/mfa/enroll", {"current_password": PASSWORD})
    assert started.status_code == 200, started.text
    secret = started.json()["secret"]
    confirmed = await post(client, "/api/auth/mfa/enroll/confirm", {"code": code(secret)})
    assert confirmed.status_code == 200, confirmed.text
    clk.advance(seconds=30)  # the enrolment code's step is spent
    return secret, confirmed.json()["recovery_codes"]


@pytest.fixture
async def admin(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory, frozen_clock: FrozenClock
) -> httpx.AsyncClient:
    await make_user(db, app.state.passwords, EMAIL, platform_admin=True)
    client = client_factory()
    response = await login(client, EMAIL)
    assert response.json()["mfa_pending"] is None  # not required outside production by default
    return client


def require_mfa(app: FastAPI) -> None:
    app.state.settings = app.state.settings.model_copy(update={"admin_mfa_required": True})


@pytest.mark.usefixtures("frozen_clock")
async def test_enrolment_needs_reauthentication_and_hides_the_secret(
    admin: httpx.AsyncClient, db: AsyncSession
) -> None:
    wrong = await post(admin, "/api/auth/mfa/enroll", {"current_password": "wrong-password-123"})
    assert wrong.status_code == 401
    started = await post(admin, "/api/auth/mfa/enroll", {"current_password": PASSWORD})
    assert started.headers["cache-control"] == "no-store"
    secret = started.json()["secret"]
    assert started.json()["otpauth_uri"].startswith("otpauth://totp/SentinelOps")
    bad = await post(admin, "/api/auth/mfa/enroll/confirm", {"code": code(secret, 5)})
    assert bad.status_code == 401 and bad.json()["error"]["code"] == "INVALID_MFA_CODE"
    ok = await post(admin, "/api/auth/mfa/enroll/confirm", {"code": code(secret)})
    codes = ok.json()["recovery_codes"]
    assert len(codes) == 10 and ok.headers["cache-control"] == "no-store"
    db.expire_all()
    row = await db.get(AdminMfa, (await db.scalar(select(AdminMfa.user_id))))
    assert row is not None and row.confirmed_at is not None and secret not in row.secret_ciphertext
    audit = json.dumps([a.safe_diff_json for a in await db.scalars(select(AuditEvent))])
    assert secret not in audit and all(c not in audit for c in codes)
    status = (await admin.get("/api/auth/mfa")).json()
    assert status == {
        "enabled": True,
        "required": False,
        "pending": None,
        "recovery_codes_left": 10,
    }


async def test_login_requires_a_fresh_code_and_rotates_the_session(
    admin: httpx.AsyncClient, client_factory: ClientFactory, frozen_clock: FrozenClock
) -> None:
    secret, _ = await enroll(admin, frozen_clock)
    other = client_factory()
    first = await login(other, EMAIL)
    assert first.json()["mfa_pending"] == "VERIFY"
    for path in ("/api/admin/dashboard", "/api/auth/sessions", f"/api/orgs/{uuid.uuid4()}"):
        blocked = await other.get(path)
        assert blocked.status_code == 401 and blocked.json()["error"]["code"] == "MFA_REQUIRED"
    me = (await other.get("/api/auth/me")).json()
    assert me["mfa_pending"] == "VERIFY" and me["is_platform_admin"] is True
    no_csrf = await other.post("/api/auth/mfa/verify", json={"code": code(secret)})
    assert no_csrf.status_code == 403  # CSRF applies to pending sessions too
    pending_cookie = dict(other.cookies)
    assert (await post(other, "/api/auth/mfa/verify", {"code": code(secret)})).status_code == 204
    assert (await other.get("/api/admin/dashboard")).status_code == 200
    replayed = client_factory()
    await login(replayed, EMAIL)
    reuse = await post(replayed, "/api/auth/mfa/verify", {"code": code(secret)})
    assert reuse.status_code == 401  # the same code can never be used twice
    stale = client_factory()
    stale.cookies.update(pending_cookie)
    assert (await stale.get("/api/auth/me")).status_code == 401  # pending session was rotated


async def test_recovery_codes_are_single_use(
    admin: httpx.AsyncClient, client_factory: ClientFactory, frozen_clock: FrozenClock
) -> None:
    _, codes = await enroll(admin, frozen_clock)
    client = client_factory()
    await login(client, EMAIL)
    used = await post(client, "/api/auth/mfa/verify", {"recovery_code": codes[0].upper()})
    assert used.status_code == 204
    assert (await client.get("/api/auth/mfa")).json()["recovery_codes_left"] == 9
    again = client_factory()
    await login(again, EMAIL)
    assert (
        await post(again, "/api/auth/mfa/verify", {"recovery_code": codes[0]})
    ).status_code == 401


async def test_repeated_failures_revoke_the_pending_session_and_throttle(
    admin: httpx.AsyncClient, client_factory: ClientFactory, frozen_clock: FrozenClock
) -> None:
    await enroll(admin, frozen_clock)
    client = client_factory()
    await login(client, EMAIL)
    for _ in range(mfa.MAX_PENDING_FAILURES):
        assert (await post(client, "/api/auth/mfa/verify", {"code": "000000"})).status_code in (
            401,
            429,
        )
    assert (await client.get("/api/auth/me")).status_code == 401  # session revoked
    blocked = client_factory()
    assert (await login(blocked, EMAIL)).status_code == 429  # account throttle shared with login


async def test_policy_forces_enrolment_and_forbids_disabling(
    app: FastAPI, admin: httpx.AsyncClient, client_factory: ClientFactory, frozen_clock: FrozenClock
) -> None:
    require_mfa(app)
    client = client_factory()
    assert (await login(client, EMAIL)).json()["mfa_pending"] == "ENROLL"
    blocked = await client.get("/api/admin/dashboard")
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "MFA_ENROLLMENT_REQUIRED"
    assert (await client.get("/api/auth/me")).json()["mfa_pending"] == "ENROLL"
    secret, _ = await enroll(client, frozen_clock)
    assert (await client.get("/api/admin/dashboard")).status_code == 200
    assert (await admin.get("/api/auth/me")).status_code == 401  # earlier sessions revoked
    refused = await post(
        client, "/api/auth/mfa/disable", {"current_password": PASSWORD, "code": code(secret)}
    )
    assert (
        refused.status_code == 409 and refused.json()["error"]["code"] == "MFA_REQUIRED_BY_POLICY"
    )


async def test_disable_and_regenerate_need_password_and_code(
    admin: httpx.AsyncClient, client_factory: ClientFactory, frozen_clock: FrozenClock
) -> None:
    secret, codes = await enroll(admin, frozen_clock)
    second = client_factory()
    await login(second, EMAIL)
    await post(second, "/api/auth/mfa/verify", {"recovery_code": codes[1]})
    wrong = await post(
        admin, "/api/auth/mfa/recovery-codes", {"current_password": PASSWORD, "code": "123456"}
    )
    assert wrong.status_code == 401
    fresh = await post(
        admin, "/api/auth/mfa/recovery-codes", {"current_password": PASSWORD, "code": code(secret)}
    )
    assert fresh.status_code == 200 and set(fresh.json()["recovery_codes"]).isdisjoint(codes)
    frozen_clock.advance(seconds=30)
    off = await post(
        admin, "/api/auth/mfa/disable", {"current_password": PASSWORD, "code": code(secret)}
    )
    assert off.status_code == 204
    assert (await second.get("/api/auth/me")).status_code == 401  # other sessions revoked
    assert (await admin.get("/api/auth/mfa")).json()["enabled"] is False


async def test_members_cannot_enrol_and_are_unaffected(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory
) -> None:
    require_mfa(app)
    user = await make_user(db, app.state.passwords, "member@acme.test")
    await make_org(db, slug="acme", created_by=user, members={user: OrgRole.OWNER})
    client = client_factory()
    assert (await login(client, "member@acme.test")).json()["mfa_pending"] is None
    refused = await post(client, "/api/auth/mfa/enroll", {"current_password": PASSWORD})
    assert refused.status_code == 403
    assert (await client.get("/api/me/organizations")).status_code == 200


async def test_operator_reset_removes_mfa_and_sessions(
    app: FastAPI, admin: httpx.AsyncClient, db: AsyncSession, frozen_clock: FrozenClock
) -> None:
    await enroll(admin, frozen_clock)
    await operator_reset(db, email=EMAIL)
    assert (await admin.get("/api/auth/me")).status_code == 401
    db.expire_all()
    assert await db.scalar(select(AdminMfa.user_id)) is None
    actions = list(await db.scalars(select(AuditEvent.action)))
    assert "platform.mfa_reset_by_operator" in actions
    require_mfa(app)
    again = await login(admin, EMAIL)
    assert again.json()["mfa_pending"] == "ENROLL"


# --- trusted proxies -----------------------------------------------------------------------------


async def test_spoofed_forwarded_headers_do_not_escape_ip_throttling(
    client_factory: ClientFactory,
) -> None:
    client = client_factory()
    for i in range(20):
        await client.post(
            "/api/auth/login",
            json={"email": f"nobody{i}@example.test", "password": "wrong-password-123"},
            headers={"X-Forwarded-For": f"198.51.100.{i}"},
        )
    locked = await client.post(
        "/api/auth/login",
        json={"email": "fresh@example.test", "password": "wrong-password-123"},
        headers={"X-Forwarded-For": "198.51.100.250"},
    )
    assert locked.status_code == 429  # the socket peer is still the client


async def test_trusted_proxy_forwarded_client_is_throttled_separately(
    app: FastAPI, client_factory: ClientFactory
) -> None:
    app.state.settings = app.state.settings.model_copy(update={"trusted_proxies": ["127.0.0.1/32"]})
    client = client_factory()
    for i in range(20):
        await client.post(
            "/api/auth/login",
            json={"email": f"nobody{i}@example.test", "password": "wrong-password-123"},
            headers={"X-Forwarded-For": "198.51.100.1"},
        )
    other_client = await client.post(
        "/api/auth/login",
        json={"email": "fresh@example.test", "password": "wrong-password-123"},
        headers={"X-Forwarded-For": "198.51.100.2"},
    )
    assert other_client.status_code == 401  # a different real client is not locked out
    same_client = await client.post(
        "/api/auth/login",
        json={"email": "fresh2@example.test", "password": "wrong-password-123"},
        headers={"X-Forwarded-For": "198.51.100.1"},
    )
    assert same_client.status_code == 429
