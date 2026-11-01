"""Authentication, sessions, CSRF/Origin, lockout, activation and password reset (G1)."""

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.audit.service import AuditAction
from sentinelops.identity.models import AuthToken, UserStatus
from sentinelops.platform.service import bootstrap_system_admin
from tests.integration.conftest import ClientFactory, FrozenClock, RecordingMailer
from tests.integration.helpers import (
    NEW_PASSWORD,
    PASSWORD,
    audit_actions,
    csrf,
    login,
    make_user,
    token_from_link,
)

pytestmark = pytest.mark.integration

EMAIL = "ada@example.test"


def _error(response: httpx.Response) -> dict[str, str]:
    body = dict(response.json()["error"])
    body.pop("request_id", None)
    return body


@pytest.fixture
async def user(app: FastAPI, db: AsyncSession) -> None:
    await make_user(db, app.state.passwords, EMAIL)


# --- login -------------------------------------------------------------------------------------


@pytest.mark.usefixtures("user")
async def test_login_success_sets_secure_session_and_audits(
    client: httpx.AsyncClient, db: AsyncSession
) -> None:
    response = await login(client, EMAIL)
    assert response.status_code == 200
    assert response.json()["email"] == EMAIL
    set_cookie = response.headers.get_list("set-cookie")
    session_cookie = next(c for c in set_cookie if c.startswith("sentinelops_session="))
    assert "HttpOnly" in session_cookie
    assert "SameSite=lax" in session_cookie
    csrf_cookie = next(c for c in set_cookie if c.startswith("sentinelops_csrf="))
    assert "HttpOnly" not in csrf_cookie

    me = await client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json() == {
        "id": me.json()["id"],
        "email": EMAIL,
        "is_platform_admin": False,
        "mfa_pending": None,
    }
    assert AuditAction.LOGIN_SUCCEEDED in await audit_actions(db)


@pytest.mark.usefixtures("user")
async def test_failed_logins_are_indistinguishable(
    app: FastAPI, client: httpx.AsyncClient, db: AsyncSession
) -> None:
    await make_user(
        db, app.state.passwords, "pending@example.test", status=UserStatus.PENDING_ACTIVATION
    )
    wrong_password = await login(client, EMAIL, "not-the-password-at-all")
    unknown = await login(client, "nobody@example.test")
    pending = await login(client, "pending@example.test")
    for response in (wrong_password, unknown, pending):
        assert response.status_code == 401
        assert _error(response) == {
            "code": "INVALID_CREDENTIALS",
            "message": "Invalid email or password",
        }
        assert "set-cookie" not in response.headers
    assert (await audit_actions(db)).count(AuditAction.LOGIN_FAILED) == 3


@pytest.mark.usefixtures("user")
async def test_account_lockout_after_five_failures_then_expires(
    client: httpx.AsyncClient, frozen_clock: FrozenClock, db: AsyncSession
) -> None:
    for _ in range(5):
        assert (await login(client, EMAIL, "wrong-password-guess")).status_code == 401
    locked = await login(client, EMAIL)  # correct password is still refused while locked
    assert locked.status_code == 429
    assert _error(locked)["code"] == "TOO_MANY_ATTEMPTS"
    assert AuditAction.LOGIN_THROTTLED in await audit_actions(db)

    frozen_clock.advance(minutes=15, seconds=1)
    assert (await login(client, EMAIL)).status_code == 200


async def test_lockout_does_not_reveal_unknown_accounts(client: httpx.AsyncClient) -> None:
    for _ in range(5):
        assert (
            await login(client, "ghost@example.test", "wrong-password-guess")
        ).status_code == 401
    assert (await login(client, "ghost@example.test")).status_code == 429


@pytest.mark.usefixtures("user")
async def test_ip_throttle_limits_password_spraying(client: httpx.AsyncClient) -> None:
    for i in range(20):
        await login(client, f"spray{i}@example.test", "wrong-password-guess")
    assert (await login(client, EMAIL)).status_code == 429


@pytest.mark.usefixtures("user")
async def test_successful_login_resets_account_counter(client: httpx.AsyncClient) -> None:
    for _ in range(4):
        await login(client, EMAIL, "wrong-password-guess")
    assert (await login(client, EMAIL)).status_code == 200
    for _ in range(4):
        await login(client, EMAIL, "wrong-password-guess")
    assert (await login(client, EMAIL)).status_code == 200


# --- sessions ----------------------------------------------------------------------------------


@pytest.mark.usefixtures("user")
async def test_session_idle_timeout(client: httpx.AsyncClient, frozen_clock: FrozenClock) -> None:
    await login(client, EMAIL)
    frozen_clock.advance(hours=7, minutes=59)
    assert (await client.get("/api/auth/me")).status_code == 200  # activity refreshes idle timer
    frozen_clock.advance(hours=8, minutes=1)
    response = await client.get("/api/auth/me")
    assert response.status_code == 401
    assert _error(response)["code"] == "UNAUTHENTICATED"


@pytest.mark.usefixtures("user")
async def test_session_absolute_expiry(
    client: httpx.AsyncClient, frozen_clock: FrozenClock
) -> None:
    await login(client, EMAIL)
    for _ in range(23):
        frozen_clock.advance(hours=1)
        assert (await client.get("/api/auth/me")).status_code == 200
    frozen_clock.advance(hours=1)
    assert (await client.get("/api/auth/me")).status_code == 401


@pytest.mark.usefixtures("user")
async def test_logout_revokes_session_server_side(
    client: httpx.AsyncClient, client_factory: ClientFactory, db: AsyncSession
) -> None:
    await login(client, EMAIL)
    stolen = client.cookies.get("sentinelops_session")
    assert stolen
    response = await client.post("/api/auth/logout", headers=csrf(client))
    assert response.status_code == 204
    replay = client_factory()
    replay.cookies.set("sentinelops_session", stolen)
    assert (await replay.get("/api/auth/me")).status_code == 401
    assert AuditAction.LOGOUT in await audit_actions(db)


@pytest.mark.usefixtures("user")
async def test_login_rotates_existing_session(
    client: httpx.AsyncClient, client_factory: ClientFactory
) -> None:
    await login(client, EMAIL)
    before = client.cookies.get("sentinelops_session")
    assert before
    await login(client, EMAIL)
    assert client.cookies.get("sentinelops_session") != before
    replay = client_factory()
    replay.cookies.set("sentinelops_session", before)
    assert (await replay.get("/api/auth/me")).status_code == 401


@pytest.mark.usefixtures("user")
async def test_revoke_other_sessions(client_factory: ClientFactory) -> None:
    laptop, phone = client_factory(), client_factory()
    await login(laptop, EMAIL)
    await login(phone, EMAIL)
    sessions = (await laptop.get("/api/auth/sessions")).json()
    assert len(sessions) == 2
    assert sum(s["current"] for s in sessions) == 1
    response = await laptop.post("/api/auth/sessions/revoke-others", headers=csrf(laptop))
    assert response.json() == {"revoked": 1}
    assert (await phone.get("/api/auth/me")).status_code == 401
    assert (await laptop.get("/api/auth/me")).status_code == 200


@pytest.mark.usefixtures("user")
async def test_change_password_rotates_session_and_revokes_others(
    client_factory: ClientFactory,
) -> None:
    laptop, phone = client_factory(), client_factory()
    await login(laptop, EMAIL)
    await login(phone, EMAIL)
    old_cookie = laptop.cookies.get("sentinelops_session")
    response = await laptop.post(
        "/api/auth/password",
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        headers=csrf(laptop),
    )
    assert response.status_code == 204
    assert laptop.cookies.get("sentinelops_session") != old_cookie
    assert (await laptop.get("/api/auth/me")).status_code == 200
    assert (await phone.get("/api/auth/me")).status_code == 401
    assert (await login(client_factory(), EMAIL, NEW_PASSWORD)).status_code == 200


@pytest.mark.usefixtures("user")
async def test_change_password_requires_current_password(client: httpx.AsyncClient) -> None:
    await login(client, EMAIL)
    response = await client.post(
        "/api/auth/password",
        json={"current_password": "wrong-current-pass", "new_password": NEW_PASSWORD},
        headers=csrf(client),
    )
    assert response.status_code == 400


# --- CSRF and Origin ---------------------------------------------------------------------------


@pytest.mark.usefixtures("user")
async def test_csrf_token_required_for_authenticated_mutations(client: httpx.AsyncClient) -> None:
    await login(client, EMAIL)
    missing = await client.post("/api/auth/logout")
    assert missing.status_code == 403
    assert _error(missing)["code"] == "CSRF_FAILED"
    wrong = await client.post("/api/auth/logout", headers={"X-CSRF-Token": "x" * 43})
    assert wrong.status_code == 403
    assert (await client.get("/api/auth/me")).status_code == 200  # session intact
    assert (await client.post("/api/auth/logout", headers=csrf(client))).status_code == 204


@pytest.mark.usefixtures("user")
async def test_csrf_token_is_bound_to_its_session(client_factory: ClientFactory) -> None:
    alice, mallory = client_factory(), client_factory()
    await login(alice, EMAIL)
    await login(mallory, EMAIL)
    response = await alice.post("/api/auth/logout", headers=csrf(mallory))
    assert response.status_code == 403


@pytest.mark.usefixtures("user")
@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Origin": "http://testserver.evil.example"},
        {"Referer": "https://evil.example/page"},
    ],
)
async def test_untrusted_origin_rejected(
    client_factory: ClientFactory, headers: dict[str, str]
) -> None:
    client = client_factory()
    client.headers.pop("Origin")
    response = await client.post(
        "/api/auth/login", json={"email": EMAIL, "password": PASSWORD}, headers=headers
    )
    assert response.status_code == 403
    assert _error(response)["code"] == "ORIGIN_REJECTED"
    assert "set-cookie" not in response.headers


@pytest.mark.usefixtures("user")
async def test_missing_origin_and_referer_rejected(client_factory: ClientFactory) -> None:
    client = client_factory()
    client.headers.pop("Origin")
    response = await client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert response.status_code == 403


@pytest.mark.usefixtures("user")
async def test_trusted_referer_accepted(client_factory: ClientFactory) -> None:
    client = client_factory()
    client.headers.pop("Origin")
    response = await client.post(
        "/api/auth/login",
        json={"email": EMAIL, "password": PASSWORD},
        headers={"Referer": "http://testserver/login"},
    )
    assert response.status_code == 200


async def test_safe_methods_skip_origin_check(client_factory: ClientFactory) -> None:
    client = client_factory()
    client.headers.pop("Origin")
    assert (await client.get("/healthz")).status_code == 200


# --- activation --------------------------------------------------------------------------------


async def _bootstrap_token(
    app: FastAPI, db: AsyncSession, email: str = "owner@example.test"
) -> str:
    url = await bootstrap_system_admin(db, app.state.settings, email=email)
    return token_from_link(url)


async def test_activation_sets_password_and_enables_login(
    app: FastAPI, client: httpx.AsyncClient, db: AsyncSession
) -> None:
    token = await _bootstrap_token(app, db)
    assert (await login(client, "owner@example.test")).status_code == 401  # not activated yet
    response = await client.post("/api/auth/activate", json={"token": token, "password": PASSWORD})
    assert response.status_code == 204
    assert (await login(client, "owner@example.test")).status_code == 200
    assert AuditAction.ACCOUNT_ACTIVATED in await audit_actions(db)


async def test_activation_token_is_single_use(
    app: FastAPI, client: httpx.AsyncClient, db: AsyncSession
) -> None:
    token = await _bootstrap_token(app, db)
    body = {"token": token, "password": PASSWORD}
    assert (await client.post("/api/auth/activate", json=body)).status_code == 204
    replay = await client.post(
        "/api/auth/activate", json={"token": token, "password": NEW_PASSWORD}
    )
    assert replay.status_code == 400
    assert _error(replay)["code"] == "INVALID_TOKEN"
    assert (await login(client, "owner@example.test", NEW_PASSWORD)).status_code == 401


async def test_activation_token_expires_after_30_minutes(
    app: FastAPI, client: httpx.AsyncClient, db: AsyncSession, frozen_clock: FrozenClock
) -> None:
    token = await _bootstrap_token(app, db)
    frozen_clock.advance(minutes=30, seconds=1)
    response = await client.post("/api/auth/activate", json={"token": token, "password": PASSWORD})
    assert response.status_code == 400


async def test_weak_password_does_not_consume_activation_token(
    app: FastAPI, client: httpx.AsyncClient, db: AsyncSession
) -> None:
    token = await _bootstrap_token(app, db)
    for weak in ("short", "aaaaaaaaaaaaaaaa", "owner-is-my-password"):
        response = await client.post("/api/auth/activate", json={"token": token, "password": weak})
        assert response.status_code == 422
        assert _error(response)["code"] == "PASSWORD_POLICY"
    ok = await client.post("/api/auth/activate", json={"token": token, "password": PASSWORD})
    assert ok.status_code == 204


async def test_unknown_activation_token_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/auth/activate", json={"token": "A" * 43, "password": PASSWORD}
    )
    assert response.status_code == 400


async def test_only_token_hash_is_stored(app: FastAPI, db: AsyncSession) -> None:
    token = await _bootstrap_token(app, db)
    stored = list(await db.scalars(select(AuthToken.token_hash)))
    assert len(stored) == 1
    assert token not in stored[0]
    assert len(stored[0]) == 64


# --- password reset ----------------------------------------------------------------------------


@pytest.mark.usefixtures("user")
async def test_reset_request_is_identical_for_unknown_accounts(
    client: httpx.AsyncClient, mailer: RecordingMailer
) -> None:
    known = await client.post("/api/auth/password-reset/request", json={"email": EMAIL})
    unknown = await client.post(
        "/api/auth/password-reset/request", json={"email": "nobody@example.test"}
    )
    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()
    assert [m.to for m in mailer.messages] == [EMAIL]


@pytest.mark.usefixtures("user")
async def test_password_reset_flow_revokes_sessions(
    client_factory: ClientFactory, mailer: RecordingMailer, db: AsyncSession
) -> None:
    signed_in, anonymous = client_factory(), client_factory()
    await login(signed_in, EMAIL)
    await anonymous.post("/api/auth/password-reset/request", json={"email": EMAIL})
    token = token_from_link(mailer.messages[-1].body)
    response = await anonymous.post(
        "/api/auth/password-reset/confirm", json={"token": token, "password": NEW_PASSWORD}
    )
    assert response.status_code == 204
    assert (await signed_in.get("/api/auth/me")).status_code == 401
    assert (await login(anonymous, EMAIL, PASSWORD)).status_code == 401
    assert (await login(anonymous, EMAIL, NEW_PASSWORD)).status_code == 200
    actions = await audit_actions(db)
    assert AuditAction.PASSWORD_RESET_REQUESTED in actions
    assert AuditAction.PASSWORD_RESET_COMPLETED in actions


@pytest.mark.usefixtures("user")
async def test_password_reset_token_replay_and_expiry(
    client: httpx.AsyncClient, mailer: RecordingMailer, frozen_clock: FrozenClock
) -> None:
    await client.post("/api/auth/password-reset/request", json={"email": EMAIL})
    token = token_from_link(mailer.messages[-1].body)
    body = {"token": token, "password": NEW_PASSWORD}
    assert (await client.post("/api/auth/password-reset/confirm", json=body)).status_code == 204
    assert (await client.post("/api/auth/password-reset/confirm", json=body)).status_code == 400

    await client.post("/api/auth/password-reset/request", json={"email": EMAIL})
    late = token_from_link(mailer.messages[-1].body)
    frozen_clock.advance(minutes=30, seconds=1)
    response = await client.post(
        "/api/auth/password-reset/confirm", json={"token": late, "password": PASSWORD}
    )
    assert response.status_code == 400


@pytest.mark.usefixtures("user")
async def test_new_reset_request_invalidates_previous_token(
    client: httpx.AsyncClient, mailer: RecordingMailer
) -> None:
    await client.post("/api/auth/password-reset/request", json={"email": EMAIL})
    first = token_from_link(mailer.messages[-1].body)
    await client.post("/api/auth/password-reset/request", json={"email": EMAIL})
    response = await client.post(
        "/api/auth/password-reset/confirm", json={"token": first, "password": NEW_PASSWORD}
    )
    assert response.status_code == 400


@pytest.mark.usefixtures("user")
async def test_reset_requests_are_rate_limited(
    client: httpx.AsyncClient, mailer: RecordingMailer
) -> None:
    for _ in range(5):
        response = await client.post("/api/auth/password-reset/request", json={"email": EMAIL})
        assert response.status_code == 202
    assert len(mailer.messages) == 3


@pytest.mark.usefixtures("user")
async def test_reset_clears_account_lockout(
    client: httpx.AsyncClient, mailer: RecordingMailer
) -> None:
    for _ in range(5):
        await login(client, EMAIL, "wrong-password-guess")
    assert (await login(client, EMAIL)).status_code == 429
    await client.post("/api/auth/password-reset/request", json={"email": EMAIL})
    token = token_from_link(mailer.messages[-1].body)
    await client.post(
        "/api/auth/password-reset/confirm", json={"token": token, "password": NEW_PASSWORD}
    )
    assert (await login(client, EMAIL, NEW_PASSWORD)).status_code == 200


@pytest.mark.usefixtures("user")
async def test_responses_never_contain_hashes(client: httpx.AsyncClient) -> None:
    response = await login(client, EMAIL)
    me = await client.get("/api/auth/me")
    sessions = await client.get("/api/auth/sessions")
    for body in (response.text, me.text, sessions.text):
        assert "argon2" not in body
        assert "hash" not in body
