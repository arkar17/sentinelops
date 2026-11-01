"""G4 incident engine and incident operations (AC-004, AC-009, AC-010, AC-017, AC-029, FR-INC-*).

Check results are mocked ``CheckOutcome`` values pushed through the real claim/complete path with
a frozen clock; no network access.
"""

import asyncio
import json
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.models import AuditEvent
from sentinelops.incidents import engine
from sentinelops.incidents.models import Incident, IncidentEvent
from sentinelops.measurements.models import Measurement
from sentinelops.probes.http.engine import CheckOutcome
from sentinelops.scheduler.models import MonitorHealth, MonitorSchedule
from sentinelops.scheduler.service import Capacity, ClaimedJob, claim_jobs, complete_job
from sentinelops.tenancy.models import OrgRole
from tests.integration.conftest import ClientFactory, FrozenClock
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

SECRET_QUERY = "s3cr3t-q"  # noqa: S105  # fictional query-string value


@dataclass
class Desk:
    app: FastAPI
    clock: FrozenClock
    org: uuid.UUID
    other_org: uuid.UUID
    monitor: uuid.UUID
    admin: httpx.AsyncClient
    member: httpx.AsyncClient
    viewer: httpx.AsyncClient
    outsider: httpx.AsyncClient
    admin_id: uuid.UUID
    member_id: uuid.UUID
    viewer_id: uuid.UUID
    outsider_id: uuid.UUID

    def url(self, path: str = "") -> str:
        return f"/api/orgs/{self.org}{path}"

    def session(self) -> AsyncSession:
        return self.app.state.sessionmaker()


@pytest.fixture
async def desk(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory, frozen_clock: FrozenClock
) -> Desk:
    pw = app.state.passwords
    admin_id = await make_user(db, pw, "admin@acme.test")
    member_id = await make_user(db, pw, "member@acme.test")
    viewer_id = await make_user(db, pw, "viewer@acme.test")
    outsider_id = await make_user(db, pw, "owner@globex.test")
    org = await make_org(
        db,
        slug="acme",
        created_by=admin_id,
        members={admin_id: OrgRole.ADMIN, member_id: OrgRole.MEMBER, viewer_id: OrgRole.VIEWER},
    )
    other = await make_org(
        db, slug="globex", created_by=outsider_id, members={outsider_id: OrgRole.OWNER}
    )
    await make_verified_domain(db, organization_id=org, fqdn="acme.example", created_by=admin_id)
    project = await make_project(db, organization_id=org, created_by=admin_id)
    clients: list[httpx.AsyncClient] = []
    for email in ("admin@acme.test", "member@acme.test", "viewer@acme.test", "owner@globex.test"):
        client = client_factory()
        assert (await login(client, email)).status_code == 200
        clients.append(client)
    admin, member, viewer, outsider = clients
    created = await admin.post(
        f"/api/orgs/{org}/monitors",
        json=monitor_body(
            project, url=f"https://api.acme.example/health?key={SECRET_QUERY}", retry_attempts=0
        ),
        headers=csrf(admin),
    )
    assert created.status_code == 201, created.text
    return Desk(
        app,
        frozen_clock,
        org,
        other,
        uuid.UUID(created.json()["id"]),
        admin,
        member,
        viewer,
        outsider,
        admin_id,
        member_id,
        viewer_id,
        outsider_id,
    )


def outcome(result: str, *, tls_days: float | None = None) -> CheckOutcome:
    failed = result == "FAIL"
    return CheckOutcome(
        result,
        failure_category="HTTP_STATUS_MISMATCH" if failed else None,
        http_status=503 if failed else 200,
        elapsed_ms=42,
        tls_not_after=clock.now() + timedelta(days=tls_days) if tls_days is not None else None,
    )


def capacity() -> Capacity:
    return Capacity(10, 10, 10, Counter(), Counter())


async def claim(desk: Desk, *, manual: bool = False, worker: str = "w-test") -> ClaimedJob:
    now = clock.now()
    values: dict[str, Any] = (
        {"manual_check_requested_at": now, "next_due_at": now + timedelta(hours=1)}
        if manual
        else {"next_due_at": now}
    )
    async with desk.session() as s:
        await s.execute(
            update(MonitorSchedule).where(MonitorSchedule.monitor_id == desk.monitor).values(values)
        )
        await s.commit()
        [job] = await claim_jobs(s, worker_id=worker, capacity=capacity(), now=now, batch=5)
    assert job.trigger == ("MANUAL" if manual else "SCHEDULED")
    return job


async def finish(desk: Desk, job: ClaimedJob, result: str, **kw: Any) -> str:
    async with desk.session() as s:
        return await complete_job(
            s, job, outcome(result, **kw), observed_at=clock.now(), now=clock.now()
        )


async def check(desk: Desk, *results: str, manual: bool = False, **kw: Any) -> None:
    for result in results:
        desk.clock.advance(seconds=60)
        job = await claim(desk, manual=manual)
        assert await finish(desk, job, result, **kw) == "recorded"


async def incidents(desk: Desk) -> list[Incident]:
    async with desk.session() as s:
        return list(
            await s.scalars(
                select(Incident)
                .where(Incident.monitor_id == desk.monitor)
                .order_by(Incident.opened_at)
            )
        )


async def events(desk: Desk, incident_id: uuid.UUID) -> list[IncidentEvent]:
    async with desk.session() as s:
        return list(
            await s.scalars(
                select(IncidentEvent)
                .where(IncidentEvent.incident_id == incident_id)
                .order_by(IncidentEvent.created_at, IncidentEvent.id)
            )
        )


async def health(desk: Desk) -> MonitorHealth:
    async with desk.session() as s:
        row = await s.get(MonitorHealth, desk.monitor)
        assert row is not None
        return row


async def post(client: httpx.AsyncClient, url: str, body: Any = None) -> httpx.Response:
    return await client.post(url, json=body, headers=csrf(client))


# --- detection --------------------------------------------------------------------------------


async def test_three_failures_open_exactly_one_outage(desk: Desk) -> None:
    await check(desk, "PASS", "FAIL", "FAIL")
    assert await incidents(desk) == []
    assert (await health(desk)).state == "UP"
    await check(desk, "FAIL")
    [incident] = await incidents(desk)
    assert (incident.type, incident.status, incident.severity) == ("OUTAGE", "OPEN", "CRITICAL")
    assert incident.opened_at == clock.now()
    assert (await health(desk)).state == "DOWN"
    await check(desk, "FAIL", "FAIL", "FAIL")
    assert len(await incidents(desk)) == 1
    [opened] = await events(desk, incident.id)
    assert (opened.event_type, opened.actor_kind) == ("OPENED", "SYSTEM")
    details = opened.details_sanitized_json
    assert details["health_to"] == "DOWN" and details["consecutive_failures"] == 3
    assert details["evidence"]["failure_category"] == "HTTP_STATUS_MISMATCH"
    assert details["evidence"]["http_status"] == 503


async def test_two_successes_resolve_and_a_new_failure_opens_a_new_incident(desk: Desk) -> None:
    await check(desk, "FAIL", "FAIL", "FAIL")
    [incident] = await incidents(desk)
    opened_at = incident.opened_at
    await check(desk, "PASS")
    assert (await incidents(desk))[0].status == "OPEN"
    await check(desk, "SLOW")
    [resolved] = await incidents(desk)
    assert (resolved.status, resolved.resolution, resolved.resolved_by) == (
        "RESOLVED",
        "AUTO",
        None,
    )
    assert resolved.resolved_at == clock.now()
    assert (await health(desk)).state == "UP"
    timeline = await events(desk, incident.id)
    assert [e.event_type for e in timeline] == ["OPENED", "RESOLVED"]
    expected = int((clock.now() - opened_at).total_seconds())
    assert timeline[1].details_sanitized_json["duration_seconds_estimate"] == expected == 120

    await check(desk, "FAIL", "FAIL", "FAIL")
    first, second = await incidents(desk)
    assert first.id == incident.id and first.status == "RESOLVED"  # never reopened
    assert second.status == "OPEN"


async def test_blocked_and_inconclusive_neither_count_nor_reset(desk: Desk) -> None:
    await check(desk, "FAIL", "FAIL", "BLOCKED", "INCONCLUSIVE")
    assert await incidents(desk) == []
    counters = await health(desk)
    assert (counters.consecutive_failures, counters.consecutive_blocked) == (2, 1)
    await check(desk, "FAIL")
    [incident] = await incidents(desk)
    assert incident.type == "OUTAGE"
    await check(desk, "BLOCKED", "INCONCLUSIVE", "PASS")
    assert (await incidents(desk))[0].status == "OPEN"  # one success so far
    await check(desk, "PASS")
    assert (await incidents(desk))[0].status == "RESOLVED"


async def test_manual_checks_never_open_or_resolve_incidents(desk: Desk) -> None:
    await check(desk, "FAIL", "FAIL")
    await check(desk, "FAIL", "FAIL", "FAIL", manual=True)
    assert await incidents(desk) == []
    assert (await health(desk)).consecutive_failures == 2
    await check(desk, "FAIL")
    [incident] = await incidents(desk)
    await check(desk, "PASS", "PASS", manual=True)
    assert (await incidents(desk))[0].status == "OPEN"
    await check(desk, "PASS", tls_days=3, manual=True)
    assert [i.id for i in await incidents(desk)] == [incident.id]  # no TLS incident either


async def test_slow_results_degrade_health_without_an_incident(desk: Desk) -> None:
    await check(desk, "PASS", "SLOW", "SLOW", "SLOW")
    assert (await health(desk)).state == "DEGRADED"
    await check(desk, "PASS", "PASS")
    assert (await health(desk)).state == "UP"
    assert await incidents(desk) == []


async def test_custom_thresholds_from_the_monitor_are_applied(desk: Desk) -> None:
    async with desk.session() as s:
        await s.execute(
            text("UPDATE monitor SET failure_threshold = 5, recovery_threshold = 3 WHERE id = :m"),
            {"m": desk.monitor},
        )
        await s.commit()
    await check(desk, "FAIL", "FAIL", "FAIL", "FAIL")
    assert await incidents(desk) == []
    await check(desk, "FAIL", "PASS", "PASS")
    assert (await incidents(desk))[0].status == "OPEN"
    await check(desk, "PASS")
    assert (await incidents(desk))[0].status == "RESOLVED"


# --- concurrency, retries and replay ------------------------------------------------------------


async def test_100_concurrent_duplicate_completions_make_one_incident(desk: Desk) -> None:
    await check(desk, "FAIL", "FAIL")
    desk.clock.advance(seconds=60)
    job = await claim(desk)
    results = await asyncio.gather(*(finish(desk, job, "FAIL") for _ in range(100)))
    assert Counter(results) == Counter({"recorded": 1, "stale": 99})
    [incident] = await incidents(desk)
    assert [e.event_type for e in await events(desk, incident.id)] == ["OPENED"]
    async with desk.session() as s:
        stored = await s.scalar(select(func.count()).where(Measurement.monitor_id == desk.monitor))
        audits = await s.scalar(
            select(func.count()).where(AuditEvent.action == "system.incident_opened")
        )
    assert (stored, audits) == (3, 1)


async def test_concurrent_duplicate_recovery_resolves_once(desk: Desk) -> None:
    await check(desk, "FAIL", "FAIL", "FAIL", "PASS")
    desk.clock.advance(seconds=60)
    job = await claim(desk)
    results = await asyncio.gather(*(finish(desk, job, "PASS") for _ in range(50)))
    assert results.count("recorded") == 1
    [incident] = await incidents(desk)
    assert incident.status == "RESOLVED"
    assert [e.event_type for e in await events(desk, incident.id)] == ["OPENED", "RESOLVED"]


async def test_worker_crash_and_replay_do_not_duplicate_transitions(desk: Desk) -> None:
    await check(desk, "FAIL", "FAIL")
    desk.clock.advance(seconds=60)
    crashed = await claim(desk, worker="crashed")
    desk.clock.advance(seconds=(crashed.lease_until - clock.now()).total_seconds() + 1)
    async with desk.session() as s:
        [rescued] = await claim_jobs(
            s, worker_id="rescuer", capacity=capacity(), now=clock.now(), batch=5
        )
    assert await finish(desk, rescued, "FAIL") == "recorded"
    assert await finish(desk, crashed, "FAIL") == "stale"  # late result of the crashed worker
    assert await finish(desk, rescued, "FAIL") == "stale"  # replayed completion
    [incident] = await incidents(desk)
    assert len(await events(desk, incident.id)) == 1
    assert (await health(desk)).consecutive_failures == 3


async def test_failed_transaction_leaves_no_partial_incident(
    desk: Desk, monkeypatch: pytest.MonkeyPatch
) -> None:
    await check(desk, "FAIL", "FAIL")
    desk.clock.advance(seconds=60)
    job = await claim(desk)

    def explode(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("audit store unavailable")

    with monkeypatch.context() as patch, pytest.raises(RuntimeError):
        patch.setattr(engine, "_audit_system", explode)
        await finish(desk, job, "FAIL")
    assert await incidents(desk) == []
    async with desk.session() as s:
        assert await s.scalar(select(func.count()).select_from(IncidentEvent)) == 0
        stored = await s.scalar(select(func.count()).where(Measurement.monitor_id == desk.monitor))
    assert stored == 2  # the measurement rolled back with the incident
    assert (await health(desk)).consecutive_failures == 2
    # The lease is still held; once it expires the job is reclaimed and evaluated exactly once.
    desk.clock.advance(seconds=(job.lease_until - clock.now()).total_seconds() + 1)
    async with desk.session() as s:
        [retry] = await claim_jobs(
            s, worker_id="retry", capacity=capacity(), now=clock.now(), batch=5
        )
    assert await finish(desk, retry, "FAIL") == "recorded"
    assert len(await incidents(desk)) == 1


async def test_out_of_order_result_is_ignored(desk: Desk) -> None:
    await check(desk, "FAIL", "FAIL")
    before = await health(desk)
    async with desk.session() as s:
        row = await s.get(MonitorHealth, desk.monitor, with_for_update=True)
        from sentinelops.catalog.models import Monitor

        monitor = await s.get(Monitor, desk.monitor)
        assert row is not None and monitor is not None
        stale = engine.Observation(
            measurement_id=uuid.uuid4(),
            result="FAIL",
            failure_category="CONNECT_ERROR",
            http_status=None,
            elapsed_ms=None,
            attempt_count=1,
            tls_not_after=None,
            observed_at=clock.now() - timedelta(minutes=5),
        )
        assert await engine.evaluate(s, monitor, row, stale) is None
        await s.commit()
    after = await health(desk)
    assert (after.consecutive_failures, after.version) == (2, before.version)
    assert await incidents(desk) == []


async def test_pause_mid_check_discards_the_result(desk: Desk) -> None:
    await check(desk, "FAIL", "FAIL")
    desk.clock.advance(seconds=60)
    job = await claim(desk)
    assert (await post(desk.admin, desk.url(f"/monitors/{desk.monitor}/pause"))).status_code == 200
    assert await finish(desk, job, "FAIL") == "stale"
    assert await incidents(desk) == []


async def test_staleness_sets_unknown_without_resolving(desk: Desk) -> None:
    await check(desk, "FAIL", "FAIL", "FAIL")
    desk.clock.advance(seconds=180)
    async with desk.session() as s:
        assert await engine.mark_stale(s, clock.now()) == 0  # exactly 3 intervals: not yet
    desk.clock.advance(seconds=1)
    async with desk.session() as s:
        assert await engine.mark_stale(s, clock.now()) == 1
        await s.commit()
    stale = await health(desk)
    assert (stale.state, stale.consecutive_failures) == ("UNKNOWN", 0)
    [incident] = await incidents(desk)
    assert incident.status == "OPEN"
    await check(desk, "PASS")
    assert ((await health(desk)).state, (await incidents(desk))[0].status) == ("UNKNOWN", "OPEN")
    await check(desk, "PASS")
    assert ((await health(desk)).state, (await incidents(desk))[0].status) == ("UP", "RESOLVED")


async def test_staleness_skips_paused_monitors(desk: Desk) -> None:
    await check(desk, "PASS")
    assert (await post(desk.admin, desk.url(f"/monitors/{desk.monitor}/pause"))).status_code == 200
    desk.clock.advance(hours=1)
    async with desk.session() as s:
        assert await engine.mark_stale(s, clock.now()) == 0


# --- TLS expiry ---------------------------------------------------------------------------------


async def test_tls_expiry_opens_once_separately_and_resolves_on_renewal(desk: Desk) -> None:
    await check(desk, "PASS", tls_days=30)
    assert await incidents(desk) == []
    await check(desk, "PASS", tls_days=10)
    [tls] = await incidents(desk)
    assert (tls.type, tls.severity, tls.status) == ("TLS_EXPIRY", "WARNING", "OPEN")
    opened = (await events(desk, tls.id))[0].details_sanitized_json
    assert (opened["days_remaining"], opened["threshold_days"]) == (10, 14)
    await check(desk, "PASS", tls_days=9)
    await check(desk, "FAIL", "FAIL", "FAIL", tls_days=9)
    kinds = {i.type: i.status for i in await incidents(desk)}
    assert kinds == {"TLS_EXPIRY": "OPEN", "OUTAGE": "OPEN"}  # separate incidents (AC-009)
    await check(desk, "FAIL")  # TLS handshake failure: no certificate data
    assert len(await incidents(desk)) == 2
    await check(desk, "PASS", tls_days=89)
    by_type = {i.type: i for i in await incidents(desk)}
    assert by_type["TLS_EXPIRY"].status == "RESOLVED"
    assert by_type["TLS_EXPIRY"].resolution == "AUTO"
    assert by_type["OUTAGE"].status == "OPEN"


async def test_tls_threshold_follows_the_monitor_setting(desk: Desk) -> None:
    async with desk.session() as s:
        await s.execute(
            text("UPDATE monitor SET tls_warn_days = 30 WHERE id = :m"), {"m": desk.monitor}
        )
        await s.commit()
    await check(desk, "PASS", tls_days=31)
    assert await incidents(desk) == []
    await check(desk, "PASS", tls_days=29)
    assert [i.type for i in await incidents(desk)] == ["TLS_EXPIRY"]


async def test_missing_tls_data_never_opens_or_resolves(desk: Desk) -> None:
    await check(desk, "PASS", "PASS")
    assert await incidents(desk) == []
    await check(desk, "PASS", tls_days=2)
    await check(desk, "PASS", "SLOW")  # no certificate observed: stays open
    [tls] = await incidents(desk)
    assert tls.status == "OPEN"


# --- operations ---------------------------------------------------------------------------------


async def open_outage(desk: Desk) -> uuid.UUID:
    await check(desk, "FAIL", "FAIL", "FAIL")
    [incident] = await incidents(desk)
    return incident.id


async def test_list_filter_and_detail(desk: Desk) -> None:
    outage = await open_outage(desk)
    await check(desk, "FAIL", tls_days=5)  # FAIL with a certificate (e.g. status mismatch)
    page = (await desk.viewer.get(desk.url("/incidents"))).json()
    assert page["total"] == 2
    assert {i["type"] for i in page["items"]} == {"OUTAGE", "TLS_EXPIRY"}
    item = next(i for i in page["items"] if i["id"] == str(outage))
    assert item["monitor"] == {
        "id": str(desk.monitor),
        "name": "Health",
        "hostname": "api.acme.example",
    }
    assert item["duration_is_estimate"] is True
    filters = {
        "type=TLS_EXPIRY": 1,
        "severity=CRITICAL": 1,
        "active=true": 2,
        "active=false": 0,
        "status=OPEN&status=ACKNOWLEDGED": 2,
        f"monitor_id={desk.monitor}": 2,
        f"monitor_id={uuid.uuid4()}": 0,
        "unassigned=true": 2,
        f"assigned_user_id={desk.member_id}": 0,
    }
    for query, expected in filters.items():
        response = await desk.member.get(desk.url(f"/incidents?{query}"))
        assert response.json()["total"] == expected, query
    assert (await desk.member.get(desk.url("/incidents?status=CLOSED"))).status_code == 422
    detail = (await desk.viewer.get(desk.url(f"/incidents/{outage}"))).json()
    assert detail["monitor_health"] == "DOWN"
    assert [e["event_type"] for e in detail["events"]] == ["OPENED"]


async def test_full_lifecycle_timeline_and_audit(desk: Desk) -> None:
    incident = await open_outage(desk)
    base = desk.url(f"/incidents/{incident}")
    acked = await post(desk.member, f"{base}/acknowledge", {"version": 1})
    assert acked.status_code == 200, acked.text
    assert acked.json()["status"] == "ACKNOWLEDGED"
    again = await post(desk.admin, f"{base}/acknowledge")
    assert again.status_code == 200
    assigned = await post(desk.member, f"{base}/assign", {"user_id": str(desk.member_id)})
    assert assigned.json()["assignee_email"] == "member@acme.test"
    noted = await post(desk.member, f"{base}/comments", {"text": "  Upstream LB restarted.\n"})
    assert noted.status_code == 201
    still_down = await post(desk.member, f"{base}/resolve")
    assert still_down.status_code == 409
    assert still_down.json()["error"]["code"] == "OUTAGE_STILL_DOWN"
    await check(desk, "PASS", "PASS")
    detail = (await desk.member.get(base)).json()
    assert detail["status"] == "RESOLVED" and detail["resolution"] == "AUTO"
    assert detail["acknowledged_at"] is not None
    assert [(e["event_type"], e["actor_kind"]) for e in detail["events"]] == [
        ("OPENED", "SYSTEM"),
        ("ACKNOWLEDGED", "USER"),
        ("ASSIGNED", "USER"),
        ("COMMENTED", "USER"),
        ("RESOLVED", "SYSTEM"),
    ]
    assert detail["events"][3]["details"] == {"text": "Upstream LB restarted."}
    assert detail["events"][1]["actor_email"] == "member@acme.test"

    async with desk.session() as s:
        audit = list(
            await s.scalars(
                select(AuditEvent).where(AuditEvent.entity_id == incident).order_by(AuditEvent.at)
            )
        )
    assert [a.action for a in audit] == [
        "system.incident_opened",
        "org.incident_acknowledged",
        "org.incident_assigned",
        "org.incident_commented",
        "system.incident_resolved",
    ]
    assert all(a.organization_id == desk.org and a.scope == "ORGANIZATION" for a in audit)
    assert audit[3].safe_diff_json == {"type": "OUTAGE", "length": 22}  # never the comment text


async def test_resolved_incidents_never_change_status_again(desk: Desk) -> None:
    incident = await open_outage(desk)
    base = desk.url(f"/incidents/{incident}")
    await check(desk, "PASS", "PASS")
    for path, body in [
        ("acknowledge", None),
        ("assign", {"user_id": str(desk.member_id)}),
        ("resolve", None),
    ]:
        response = await post(desk.member, f"{base}/{path}", body)
        assert response.status_code == 409, path
        assert response.json()["error"]["code"] == "INCIDENT_RESOLVED"
    assert (
        await post(desk.member, f"{base}/comments", {"text": "Postmortem link"})
    ).status_code == 201


async def test_manual_resolve_allowed_when_paused_and_for_tls(desk: Desk) -> None:
    outage = await open_outage(desk)
    assert (await post(desk.admin, desk.url(f"/monitors/{desk.monitor}/pause"))).status_code == 200
    resolved = await post(
        desk.member, desk.url(f"/incidents/{outage}/resolve"), {"note": "Planned migration"}
    )
    assert resolved.status_code == 200, resolved.text
    body = resolved.json()
    assert (body["resolution"], body["status"]) == ("MANUAL", "RESOLVED")
    assert body["events"][-1]["details"]["note"] == "Planned migration"
    async with desk.session() as s:
        row = await s.get(Incident, outage)
        assert row is not None and row.resolved_by == desk.member_id


async def test_manual_tls_resolve_is_permitted(desk: Desk) -> None:
    await check(desk, "PASS", tls_days=3)
    [tls] = await incidents(desk)
    response = await post(desk.member, desk.url(f"/incidents/{tls.id}/resolve"))
    assert response.status_code == 200


async def test_version_conflict_and_invalid_input(desk: Desk) -> None:
    incident = await open_outage(desk)
    base = desk.url(f"/incidents/{incident}")
    stale = await post(desk.member, f"{base}/acknowledge", {"version": 7})
    assert stale.json()["error"]["code"] == "VERSION_CONFLICT"
    bad = await post(desk.member, f"{base}/comments", {"text": "bad\x00text"})
    assert bad.status_code == 422 and "bad" not in bad.text
    blank = await post(desk.member, f"{base}/comments", {"text": "   "})
    assert blank.status_code == 422
    long = await post(desk.member, f"{base}/comments", {"text": "x" * 2001})
    assert long.status_code == 422


async def test_assignment_requires_an_active_member_of_this_organization(
    desk: Desk, db: AsyncSession
) -> None:
    incident = await open_outage(desk)
    url = desk.url(f"/incidents/{incident}/assign")
    outsider = await post(desk.member, url, {"user_id": str(desk.outsider_id)})
    assert outsider.status_code == 422
    assert outsider.json()["error"]["code"] == "ASSIGNEE_NOT_MEMBER"
    unknown = await post(desk.member, url, {"user_id": str(uuid.uuid4())})
    assert unknown.json()["error"]["code"] == "ASSIGNEE_NOT_MEMBER"
    viewer = await post(desk.member, url, {"user_id": str(desk.viewer_id)})
    assert viewer.status_code == 200  # any ACTIVE member, including VIEWER
    suspend = await desk.admin.put(
        desk.url(f"/members/{desk.viewer_id}/status"),
        json={"status": "SUSPENDED"},
        headers=csrf(desk.admin),
    )
    assert suspend.status_code in (200, 204), suspend.text
    detail = (await desk.member.get(desk.url(f"/incidents/{incident}"))).json()
    assert detail["assigned_user_id"] is None  # unassigned with the membership (FR-ORG-004)
    last = detail["events"][-1]
    assert (last["event_type"], last["actor_kind"]) == ("UNASSIGNED", "SYSTEM")
    assert last["details"]["reason"] == "MEMBERSHIP_INACTIVE"
    again = await post(desk.member, url, {"user_id": str(desk.viewer_id)})
    assert again.json()["error"]["code"] == "ASSIGNEE_NOT_MEMBER"
    unassign = await post(desk.member, url, {"user_id": None})
    assert unassign.status_code == 200


async def test_member_removal_unassigns_open_incidents(desk: Desk) -> None:
    incident = await open_outage(desk)
    await post(
        desk.member, desk.url(f"/incidents/{incident}/assign"), {"user_id": str(desk.member_id)}
    )
    removed = await desk.admin.delete(
        desk.url(f"/members/{desk.member_id}"), headers=csrf(desk.admin)
    )
    assert removed.status_code in (200, 204), removed.text
    detail = (await desk.admin.get(desk.url(f"/incidents/{incident}"))).json()
    assert detail["assigned_user_id"] is None


async def test_concurrent_acknowledge_and_resolve_apply_once(desk: Desk) -> None:
    incident = await open_outage(desk)
    base = desk.url(f"/incidents/{incident}")
    acks = await asyncio.gather(
        *(post(c, f"{base}/acknowledge") for c in [desk.member, desk.admin] * 10)
    )
    assert all(r.status_code == 200 for r in acks)
    assert (await post(desk.admin, desk.url(f"/monitors/{desk.monitor}/pause"))).status_code == 200
    resolves = await asyncio.gather(
        *(post(c, f"{base}/resolve") for c in [desk.member, desk.admin] * 5)
    )
    assert sorted(r.status_code for r in resolves) == [200] + [409] * 9
    kinds = [e.event_type for e in await events(desk, incident)]
    assert kinds == ["OPENED", "ACKNOWLEDGED", "RESOLVED"]


async def test_concurrent_manual_resolve_and_worker_failure_stay_consistent(desk: Desk) -> None:
    """A manual resolve racing a worker evaluation never leaves an ACTIVE+DOWN monitor without
    its outage, and never produces two active outages."""
    await check(desk, "FAIL", "FAIL", "FAIL")
    [incident] = await incidents(desk)
    await check(desk, "PASS")  # still DOWN (1 of 2)
    assert (await post(desk.admin, desk.url(f"/monitors/{desk.monitor}/pause"))).status_code == 200
    assert (await post(desk.admin, desk.url(f"/monitors/{desk.monitor}/resume"))).status_code == 200
    # Health is UNKNOWN after resume; a FAIL streak races a manual resolve.
    await check(desk, "FAIL", "FAIL")
    desk.clock.advance(seconds=60)
    job = await claim(desk)
    resolve, finished = await asyncio.gather(
        post(desk.member, desk.url(f"/incidents/{incident.id}/resolve")),
        finish(desk, job, "FAIL"),
    )
    assert finished == "recorded"
    rows = await incidents(desk)
    active = [i for i in rows if i.status != "RESOLVED"]
    assert len(active) == 1  # either the original stayed open, or a new one opened
    if resolve.status_code == 200:
        assert active[0].id != incident.id
    else:
        assert resolve.json()["error"]["code"] == "OUTAGE_STILL_DOWN"
        assert active[0].id == incident.id


# --- isolation, permissions and data hygiene ----------------------------------------------------


async def test_viewer_reads_but_cannot_act(desk: Desk) -> None:
    incident = await open_outage(desk)
    base = desk.url(f"/incidents/{incident}")
    assert (await desk.viewer.get(base)).status_code == 200
    for path, body in [
        ("acknowledge", None),
        ("assign", {"user_id": str(desk.viewer_id)}),
        ("comments", {"text": "hi"}),
        ("resolve", None),
    ]:
        response = await post(desk.viewer, f"{base}/{path}", body)
        assert response.status_code == 403, path


async def test_other_organizations_get_404_everywhere(
    desk: Desk, app: FastAPI, db: AsyncSession
) -> None:
    incident = await open_outage(desk)
    for org in (desk.org, desk.other_org):
        base = f"/api/orgs/{org}/incidents"
        if org == desk.org:
            assert (await desk.outsider.get(base)).status_code == 404
        else:
            assert (await desk.outsider.get(base)).json() == {"items": [], "total": 0}
        assert (await desk.outsider.get(f"{base}/{incident}")).status_code == 404
        for path, body in [
            ("acknowledge", None),
            ("assign", {"user_id": str(desk.outsider_id)}),
            ("comments", {"text": "probe"}),
            ("resolve", None),
        ]:
            response = await post(desk.outsider, f"{base}/{incident}/{path}", body)
            assert response.status_code == 404, (org, path)
    assert [e.event_type for e in await events(desk, incident)] == ["OPENED"]


async def test_system_admin_without_membership_gets_404(
    desk: Desk, app: FastAPI, db: AsyncSession, client_factory: ClientFactory
) -> None:
    incident = await open_outage(desk)
    await make_user(db, app.state.passwords, "root@platform.test", platform_admin=True)
    root = client_factory()
    await login(root, "root@platform.test")
    assert (await root.get(desk.url("/incidents"))).status_code == 404
    assert (await root.get(desk.url(f"/incidents/{incident}"))).status_code == 404
    platform_audit = (await root.get("/api/admin/audit")).json()
    assert "incident" not in json.dumps(platform_audit)


async def test_incident_data_never_contains_url_secrets(desk: Desk) -> None:
    incident = await open_outage(desk)
    await check(desk, "PASS", tls_days=4)
    await post(desk.member, desk.url(f"/incidents/{incident}/acknowledge"))
    payloads = [
        (await desk.admin.get(desk.url("/incidents"))).text,
        (await desk.admin.get(desk.url(f"/incidents/{incident}"))).text,
        (await desk.admin.get(desk.url("/audit"))).text,
    ]
    async with desk.session() as s:
        payloads.append(
            json.dumps([e.details_sanitized_json for e in await s.scalars(select(IncidentEvent))])
        )
        payloads.extend(i.title_sanitized for i in await s.scalars(select(Incident)))
    for payload in payloads:
        assert SECRET_QUERY not in payload
        assert "?key" not in payload
        assert "/health" not in payload


async def test_database_constraints(desk: Desk, owner_engine: Any) -> None:
    incident = await open_outage(desk)
    async with desk.session() as s:
        # AC-029: the assignee must be a member of the incident's own organization.
        with pytest.raises(IntegrityError):
            await s.execute(
                update(Incident)
                .where(Incident.id == incident)
                .values(assigned_user_id=desk.outsider_id)
            )
        await s.rollback()
        # At most one active incident per (monitor, type).
        with pytest.raises(IntegrityError):
            await s.execute(
                text(
                    "INSERT INTO incident (id, organization_id, monitor_id, type, source_kind, "
                    "severity, status, title_sanitized, opened_at, last_event_at, version) "
                    "VALUES (:id, :org, :m, 'OUTAGE', 'HTTP_PROBE', 'CRITICAL', 'OPEN', 'x', "
                    "now(), now(), 1)"
                ),
                {"id": uuid.uuid4(), "org": desk.org, "m": desk.monitor},
            )
        await s.rollback()
        # An incident cannot point at another organization's monitor.
        with pytest.raises(IntegrityError):
            await s.execute(
                text(
                    "INSERT INTO incident (id, organization_id, monitor_id, type, source_kind, "
                    "severity, status, title_sanitized, opened_at, last_event_at, version) "
                    "VALUES (:id, :org, :m, 'TLS_EXPIRY', 'HTTP_PROBE', 'WARNING', 'OPEN', 'x', "
                    "now(), now(), 1)"
                ),
                {"id": uuid.uuid4(), "org": desk.other_org, "m": desk.monitor},
            )
        await s.rollback()
        # A second OPENED event for the same incident is rejected (replay safety).
        with pytest.raises(IntegrityError):
            await s.execute(
                text(
                    "INSERT INTO incident_event (id, organization_id, incident_id, actor_kind, "
                    "event_type, details_sanitized_json, created_at) "
                    "VALUES (:id, :org, :i, 'SYSTEM', 'OPENED', '{}', now())"
                ),
                {"id": uuid.uuid4(), "org": desk.org, "i": incident},
            )
        await s.rollback()
        # The timeline is append-only for the application role.
        for statement in (
            "UPDATE incident_event SET details_sanitized_json = '{}'",
            "DELETE FROM incident_event",
            "DELETE FROM incident",
        ):
            with pytest.raises(DBAPIError, match="permission denied"):
                await s.execute(text(statement))
            await s.rollback()
        # A resolved incident must carry its resolution time and kind.
        with pytest.raises(IntegrityError):
            await s.execute(
                update(Incident).where(Incident.id == incident).values(status="RESOLVED")
            )
        await s.rollback()


@pytest.mark.parametrize("role", [OrgRole.OWNER, OrgRole.ADMIN, OrgRole.MEMBER, OrgRole.VIEWER])
async def test_incident_actions_follow_the_permission_matrix(
    desk: Desk, db: AsyncSession, client_factory: ClientFactory, role: str
) -> None:
    from sentinelops.authz.matrix import allows
    from sentinelops.tenancy.models import MemberStatus, OrganizationMember

    incident = await open_outage(desk)
    user = await make_user(db, desk.app.state.passwords, f"{role.lower()}@role.test")
    db.add(
        OrganizationMember(
            organization_id=desk.org,
            user_id=user,
            role=role,
            status=MemberStatus.ACTIVE,
            joined_at=clock.now(),
            status_changed_at=clock.now(),
        )
    )
    await db.commit()
    client = client_factory()
    await login(client, f"{role.lower()}@role.test")
    base = desk.url(f"/incidents/{incident}")
    calls: list[tuple[str, str, Any]] = [
        ("INC.view", "GET", None),
        ("INC.acknowledge", "acknowledge", None),
        ("INC.assign", "assign", {"user_id": str(user)}),
        ("INC.comment", "comments", {"text": "note"}),
        ("INC.resolve", "resolve", None),  # allowed roles get 409 OUTAGE_STILL_DOWN
    ]
    for action, path, body in calls:
        if path == "GET":
            response = await client.get(base)
        else:
            response = await post(client, f"{base}/{path}", body)
        if allows(role, action):
            assert response.status_code in (200, 201, 409), (action, response.text)
            if response.status_code == 409:
                assert response.json()["error"]["code"] == "OUTAGE_STILL_DOWN"
        else:
            assert response.status_code == 403, action
