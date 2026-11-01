"""SYSTEM_ADMIN bootstrap, platform admin lifecycle and platform authorization (G1)."""

import asyncio
import os
import sys
import uuid

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.audit.models import AuditEvent
from sentinelops.audit.service import AuditAction
from sentinelops.errors import AppError
from sentinelops.identity.models import AppUser, UserStatus
from sentinelops.platform.models import PlatformAdmin, PlatformAdminStatus
from sentinelops.platform.service import (
    BootstrapRefusedError,
    bootstrap_system_admin,
    deactivate_admin,
    recover_system_admin,
)
from tests.integration.conftest import (
    ClientFactory,
    DisposableDatabase,
    FrozenClock,
    RecordingMailer,
)
from tests.integration.helpers import (
    PASSWORD,
    audit_actions,
    csrf,
    login,
    make_user,
    token_from_link,
)

pytestmark = pytest.mark.integration

ADMIN = "root@example.test"
OTHER_ADMIN = "second@example.test"
MEMBER = "member@example.test"


@pytest.fixture
async def admin_client(
    app: FastAPI, db: AsyncSession, client: httpx.AsyncClient
) -> httpx.AsyncClient:
    await make_user(db, app.state.passwords, ADMIN, platform_admin=True)
    assert (await login(client, ADMIN)).status_code == 200
    return client


@pytest.fixture
async def member_client(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory
) -> httpx.AsyncClient:
    await make_user(db, app.state.passwords, MEMBER)
    client = client_factory()
    assert (await login(client, MEMBER)).status_code == 200
    return client


# --- bootstrap ---------------------------------------------------------------------------------


async def test_bootstrap_creates_pending_admin_without_password(
    app: FastAPI, db: AsyncSession
) -> None:
    url = await bootstrap_system_admin(db, app.state.settings, email="Owner@Example.test")
    assert url.startswith("http://localhost:5173/activate#token=")
    user = await db.scalar(select(AppUser).where(AppUser.email_normalized == "owner@example.test"))
    assert user is not None
    assert user.status == UserStatus.PENDING_ACTIVATION
    assert user.password_hash is None
    admin = await db.get(PlatformAdmin, user.id)
    assert admin is not None
    assert admin.status == PlatformAdminStatus.ACTIVE
    assert admin.granted_by is None
    event = await db.scalar(select(AuditEvent).where(AuditEvent.action == AuditAction.BOOTSTRAP))
    assert event is not None
    assert event.actor_kind == "CLI"
    assert token_from_link(url) not in str(event.safe_diff_json)


async def test_second_bootstrap_is_refused(app: FastAPI, db: AsyncSession) -> None:
    await bootstrap_system_admin(db, app.state.settings, email="owner@example.test")
    with pytest.raises(BootstrapRefusedError, match="already exists"):
        await bootstrap_system_admin(db, app.state.settings, email="intruder@example.test")
    assert await db.scalar(select(func.count()).select_from(AppUser)) == 1


async def test_concurrent_bootstrap_creates_exactly_one_admin(
    app: FastAPI, db: AsyncSession
) -> None:
    async def attempt(i: int) -> str | None:
        async with app.state.sessionmaker() as session:
            try:
                return await bootstrap_system_admin(
                    session, app.state.settings, email=f"race{i}@example.test"
                )
            except BootstrapRefusedError:
                return None

    results = await asyncio.gather(*(attempt(i) for i in range(6)))
    assert sum(r is not None for r in results) == 1
    assert await db.scalar(select(func.count()).select_from(PlatformAdmin)) == 1
    assert await db.scalar(select(func.count()).select_from(AppUser)) == 1


async def test_recover_resets_admin_and_revokes_sessions(
    app: FastAPI, db: AsyncSession, client: httpx.AsyncClient
) -> None:
    await make_user(db, app.state.passwords, ADMIN, platform_admin=True)
    await login(client, ADMIN)
    url = await recover_system_admin(db, app.state.settings, email=ADMIN)
    assert (await client.get("/api/auth/me")).status_code == 401
    assert (await login(client, ADMIN)).status_code == 401
    response = await client.post(
        "/api/auth/activate",
        json={"token": token_from_link(url), "password": "fresh-passphrase-99"},
    )
    assert response.status_code == 204
    assert (await login(client, ADMIN, "fresh-passphrase-99")).status_code == 200
    assert AuditAction.RECOVERY in await audit_actions(db)


async def test_recover_refuses_non_admins(app: FastAPI, db: AsyncSession) -> None:
    await make_user(db, app.state.passwords, MEMBER)
    with pytest.raises(BootstrapRefusedError):
        await recover_system_admin(db, app.state.settings, email=MEMBER)


async def _run_cli(test_database: DisposableDatabase, *args: str) -> tuple[int, str, str]:
    env = {
        **os.environ,
        "SENTINELOPS_DATABASE_URL": test_database.app_url,
        "SENTINELOPS_ENV": "test",
        "SENTINELOPS_LOG_LEVEL": "DEBUG",
    }
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "sentinelops.cli",
        *args,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    return process.returncode or 0, stdout.decode(), stderr.decode()


@pytest.mark.usefixtures("owner_engine")
async def test_cli_bootstrap_prints_link_only_to_terminal(
    test_database: DisposableDatabase,
) -> None:
    code, out, err = await _run_cli(
        test_database, "bootstrap-system-admin", "--email", "cli-owner@example.test"
    )
    assert code == 0, err
    token = token_from_link(out)
    log_lines = [line for line in out.splitlines() if line.startswith("{")]
    assert all(token not in line for line in log_lines)
    assert token not in err

    code, out, err = await _run_cli(
        test_database, "bootstrap-system-admin", "--email", "cli-other@example.test"
    )
    assert code == 1
    assert "Refused" in err
    assert "#token=" not in out


# --- platform authorization --------------------------------------------------------------------

ADMIN_ROUTES = [
    ("GET", "/api/admin/dashboard"),
    ("GET", "/api/admin/platform-admins"),
    ("POST", "/api/admin/platform-admins"),
    ("POST", f"/api/admin/platform-admins/{uuid.uuid4()}/deactivate"),
    ("POST", f"/api/admin/platform-admins/invitations/{uuid.uuid4()}/revoke"),
    ("GET", "/api/admin/settings"),
    ("PUT", "/api/admin/settings"),
    ("GET", "/api/admin/audit"),
]


@pytest.mark.parametrize(("method", "path"), ADMIN_ROUTES)
async def test_platform_routes_reject_ordinary_users(
    member_client: httpx.AsyncClient, method: str, path: str
) -> None:
    response = await member_client.request(
        method, path, json={"email": "me@example.test"}, headers=csrf(member_client)
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.parametrize(("method", "path"), ADMIN_ROUTES)
async def test_platform_routes_require_authentication(
    client: httpx.AsyncClient, method: str, path: str
) -> None:
    response = await client.request(method, path, json={})
    assert response.status_code == 401


async def test_ordinary_user_cannot_grant_self_platform_role(
    member_client: httpx.AsyncClient, db: AsyncSession, mailer: RecordingMailer
) -> None:
    invite = await member_client.post(
        "/api/admin/platform-admins", json={"email": MEMBER}, headers=csrf(member_client)
    )
    assert invite.status_code == 403
    forged = await member_client.post(
        "/api/auth/platform-invitations/accept",
        json={"token": "B" * 43},
        headers=csrf(member_client),
    )
    assert forged.status_code == 400
    assert mailer.messages == []
    assert await db.scalar(select(func.count()).select_from(PlatformAdmin)) == 0
    me = await member_client.get("/api/auth/me")
    assert me.json()["is_platform_admin"] is False


async def test_deactivated_admin_loses_platform_access(
    app: FastAPI, db: AsyncSession, admin_client: httpx.AsyncClient, client_factory: ClientFactory
) -> None:
    other_id = await make_user(db, app.state.passwords, OTHER_ADMIN, platform_admin=True)
    other = client_factory()
    await login(other, OTHER_ADMIN)
    assert (await other.get("/api/admin/dashboard")).status_code == 200

    response = await admin_client.post(
        f"/api/admin/platform-admins/{other_id}/deactivate", headers=csrf(admin_client)
    )
    assert response.status_code == 204
    assert (await other.get("/api/admin/dashboard")).status_code == 401  # sessions revoked
    await login(other, OTHER_ADMIN)  # the global account still works
    assert (await other.get("/api/auth/me")).json()["is_platform_admin"] is False
    assert (await other.get("/api/admin/dashboard")).status_code == 403
    assert AuditAction.ADMIN_DEACTIVATED in await audit_actions(db)


async def test_admin_cannot_deactivate_self(
    app: FastAPI, db: AsyncSession, admin_client: httpx.AsyncClient
) -> None:
    me = (await admin_client.get("/api/auth/me")).json()
    response = await admin_client.post(
        f"/api/admin/platform-admins/{me['id']}/deactivate", headers=csrf(admin_client)
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CANNOT_DEACTIVATE_SELF"


async def test_last_active_admin_cannot_be_deactivated(app: FastAPI, db: AsyncSession) -> None:
    actor = await make_user(db, app.state.passwords, ADMIN, platform_admin=True)
    target = await make_user(db, app.state.passwords, OTHER_ADMIN, platform_admin=True)
    # The actor's own account becomes unusable, so the target is the last usable admin.
    user = await db.get(AppUser, actor)
    assert user is not None
    user.status = UserStatus.DISABLED
    await db.commit()
    with pytest.raises(AppError, match="last active platform administrator"):
        await deactivate_admin(db, actor_id=actor, target_user_id=target)
    await db.rollback()


async def test_concurrent_mutual_deactivation_keeps_one_admin(
    app: FastAPI, db: AsyncSession
) -> None:
    a = await make_user(db, app.state.passwords, ADMIN, platform_admin=True)
    b = await make_user(db, app.state.passwords, OTHER_ADMIN, platform_admin=True)

    async def attempt(actor: uuid.UUID, target: uuid.UUID) -> bool:
        async with app.state.sessionmaker() as session:
            try:
                await deactivate_admin(session, actor_id=actor, target_user_id=target)
            except AppError:
                return False
            return True

    results = await asyncio.gather(attempt(a, b), attempt(b, a))
    active = await db.scalar(
        select(func.count())
        .select_from(PlatformAdmin)
        .where(PlatformAdmin.status == PlatformAdminStatus.ACTIVE)
    )
    assert (active or 0) >= 1
    assert sum(results) <= 1


# --- invitations -------------------------------------------------------------------------------


async def _invite(admin_client: httpx.AsyncClient, email: str) -> httpx.Response:
    return await admin_client.post(
        "/api/admin/platform-admins", json={"email": email}, headers=csrf(admin_client)
    )


async def test_invitation_creates_new_admin_account(
    admin_client: httpx.AsyncClient,
    client_factory: ClientFactory,
    mailer: RecordingMailer,
    db: AsyncSession,
) -> None:
    response = await _invite(admin_client, "New.Admin@example.test")
    assert response.status_code == 201
    assert "token" not in response.text
    assert [m.to for m in mailer.messages] == ["new.admin@example.test"]
    token = token_from_link(mailer.messages[0].body)

    invitee = client_factory()
    accepted = await invitee.post(
        "/api/auth/platform-invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert accepted.status_code == 204
    await login(invitee, "new.admin@example.test")
    assert (await invitee.get("/api/admin/dashboard")).status_code == 200

    replay = await client_factory().post(
        "/api/auth/platform-invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert replay.status_code == 400
    actions = await audit_actions(db)
    assert AuditAction.ADMIN_INVITED in actions
    assert AuditAction.ADMIN_INVITATION_ACCEPTED in actions


async def test_invitation_expires_after_24_hours(
    admin_client: httpx.AsyncClient,
    client_factory: ClientFactory,
    mailer: RecordingMailer,
    frozen_clock: FrozenClock,
) -> None:
    await _invite(admin_client, "late@example.test")
    token = token_from_link(mailer.messages[0].body)
    frozen_clock.advance(hours=24, seconds=1)
    response = await client_factory().post(
        "/api/auth/platform-invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert response.status_code == 400


async def test_revoked_and_superseded_invitations_are_unusable(
    admin_client: httpx.AsyncClient, client_factory: ClientFactory, mailer: RecordingMailer
) -> None:
    await _invite(admin_client, "twice@example.test")
    first = token_from_link(mailer.messages[0].body)
    second_response = await _invite(admin_client, "twice@example.test")
    second = token_from_link(mailer.messages[1].body)
    accept = client_factory()
    body = {"token": first, "password": PASSWORD}
    assert (
        await accept.post("/api/auth/platform-invitations/accept", json=body)
    ).status_code == 400

    invitation_id = second_response.json()["id"]
    revoke = await admin_client.post(
        f"/api/admin/platform-admins/invitations/{invitation_id}/revoke",
        headers=csrf(admin_client),
    )
    assert revoke.status_code == 204
    body = {"token": second, "password": PASSWORD}
    assert (
        await accept.post("/api/auth/platform-invitations/accept", json=body)
    ).status_code == 400


async def test_existing_account_must_sign_in_as_invitee(
    app: FastAPI,
    db: AsyncSession,
    admin_client: httpx.AsyncClient,
    member_client: httpx.AsyncClient,
    client_factory: ClientFactory,
    mailer: RecordingMailer,
) -> None:
    await make_user(db, app.state.passwords, "existing@example.test")
    await _invite(admin_client, "existing@example.test")
    token = token_from_link(mailer.messages[0].body)

    anonymous = await client_factory().post(
        "/api/auth/platform-invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert anonymous.status_code == 401
    assert anonymous.json()["error"]["code"] == "SIGN_IN_REQUIRED"

    wrong_user = await member_client.post(
        "/api/auth/platform-invitations/accept", json={"token": token}, headers=csrf(member_client)
    )
    assert wrong_user.status_code == 401
    assert (await member_client.get("/api/auth/me")).json()["is_platform_admin"] is False

    invitee = client_factory()
    await login(invitee, "existing@example.test")
    accepted = await invitee.post(
        "/api/auth/platform-invitations/accept", json={"token": token}, headers=csrf(invitee)
    )
    assert accepted.status_code == 204
    assert (await invitee.get("/api/auth/me")).status_code == 401  # rotated on privilege change
    await login(invitee, "existing@example.test")
    assert (await invitee.get("/api/auth/me")).json()["is_platform_admin"] is True


async def test_inviting_an_active_admin_conflicts(admin_client: httpx.AsyncClient) -> None:
    response = await _invite(admin_client, ADMIN)
    assert response.status_code == 409


async def test_invitation_email_failure_is_reported(
    admin_client: httpx.AsyncClient, mailer: RecordingMailer
) -> None:
    mailer.fail = True
    response = await _invite(admin_client, "unlucky@example.test")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "MAIL_DELIVERY_FAILED"


async def test_admin_listing_exposes_no_secrets(
    admin_client: httpx.AsyncClient, mailer: RecordingMailer
) -> None:
    await _invite(admin_client, "pending@example.test")
    token = token_from_link(mailer.messages[0].body)
    response = await admin_client.get("/api/admin/platform-admins")
    assert response.status_code == 200
    body = response.json()
    assert [a["email"] for a in body["admins"]] == [ADMIN]
    assert [i["email"] for i in body["invitations"]] == ["pending@example.test"]
    assert token not in response.text
    assert "hash" not in response.text


# --- settings, dashboard, audit ----------------------------------------------------------------


async def test_settings_update_with_version_check(
    admin_client: httpx.AsyncClient, db: AsyncSession
) -> None:
    current = (await admin_client.get("/api/admin/settings")).json()
    assert current["default_max_monitors"] == 20
    payload = {k: v for k, v in current.items() if k != "updated_at"}
    payload["default_max_monitors"] = 50
    updated = await admin_client.put(
        "/api/admin/settings", json=payload, headers=csrf(admin_client)
    )
    assert updated.status_code == 200
    assert updated.json()["default_max_monitors"] == 50
    assert updated.json()["version"] == current["version"] + 1

    stale = await admin_client.put("/api/admin/settings", json=payload, headers=csrf(admin_client))
    assert stale.status_code == 409

    payload["version"] = updated.json()["version"]
    payload["max_custom_headers"] = 6  # above the OD-07 cap
    invalid = await admin_client.put(
        "/api/admin/settings", json=payload, headers=csrf(admin_client)
    )
    assert invalid.status_code == 422

    event = await db.scalar(
        select(AuditEvent).where(AuditEvent.action == AuditAction.SETTINGS_UPDATED)
    )
    assert event is not None
    assert event.safe_diff_json["changes"] == {"default_max_monitors": {"from": 20, "to": 50}}


async def test_dashboard_and_audit_history(admin_client: httpx.AsyncClient) -> None:
    dashboard = (await admin_client.get("/api/admin/dashboard")).json()
    assert dashboard["active_admins"] == 1
    assert dashboard["pending_invitations"] == 0
    assert dashboard["recent_audit"][0]["action"] == AuditAction.LOGIN_SUCCEEDED
    audit = (await admin_client.get("/api/admin/audit", params={"limit": 5})).json()
    assert audit[0]["actor_email"] == ADMIN


# --- database privileges -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_event SET action = 'tampered'",
        "DELETE FROM audit_event",
        "DELETE FROM app_user",
        "DELETE FROM platform_admin",
        "CREATE TABLE intruder (id int)",
        "DROP TABLE platform_settings",
    ],
)
async def test_app_role_is_least_privilege(db: AsyncSession, statement: str) -> None:
    with pytest.raises(DBAPIError, match=r"permission denied|must be owner"):
        await db.execute(text(statement))
    await db.rollback()
