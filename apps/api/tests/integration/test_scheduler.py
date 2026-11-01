"""Worker scheduling, leases, concurrency and result recording against mocked probe targets."""

import asyncio
import uuid
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import httpcore
import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.catalog.models import DomainStatus, Monitor, VerifiedDomain
from sentinelops.config import Settings
from sentinelops.measurements.models import Measurement
from sentinelops.probes.http.engine import ProbeEnvironment
from sentinelops.scheduler.loop import Worker
from sentinelops.scheduler.models import MonitorHealth, MonitorSchedule, WorkerHeartbeat
from sentinelops.scheduler.runner import JobRunner
from sentinelops.scheduler.service import Capacity, claim_jobs, complete_job
from sentinelops.tenancy.models import Organization, OrgRole
from tests.integration.conftest import ClientFactory, FakeTxt, FrozenClock
from tests.integration.helpers import (
    csrf,
    login,
    make_org,
    make_project,
    make_user,
    make_verified_domain,
    monitor_body,
)
from tests.probe.fakes import FakeBackend, FakeServer

pytestmark = pytest.mark.integration

PUBLIC = "93.184.216.34"
SLOW_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


@dataclass
class Resolver:
    answers: dict[str, list[str]] = field(default_factory=dict[str, list[str]])
    calls: list[str] = field(default_factory=list[str])

    async def __call__(self, hostname: str, port: int) -> Sequence[str]:
        self.calls.append(hostname)
        return self.answers.get(hostname, [PUBLIC])


@dataclass
class Fleet:
    app: FastAPI
    org: uuid.UUID
    project: uuid.UUID
    admin: httpx.AsyncClient
    server: FakeServer
    resolver: Resolver
    txt: FakeTxt
    settings: Settings

    def url(self, path: str = "") -> str:
        return f"/api/orgs/{self.org}{path}"

    def worker(self, *, environment: ProbeEnvironment | None = None, **overrides: object) -> Worker:
        settings = self.settings.model_copy(update=overrides)
        env = environment or ProbeEnvironment(
            resolver=self.resolver, inner_backend=FakeBackend(self.server), retry_delay_seconds=0
        )
        runner = JobRunner(self.app.state.sessionmaker, self.app.state.secret_box, env)
        return Worker(self.app.state.sessionmaker, runner, settings, self.txt)

    async def monitor(self, host: str = "api.acme.example", **extra: object) -> uuid.UUID:
        body = monitor_body(self.project, url=f"https://{host}/health", retry_attempts=0, **extra)
        response = await self.admin.post(self.url("/monitors"), json=body, headers=csrf(self.admin))
        assert response.status_code == 201, response.text
        assert response.json()["lifecycle"] == "ACTIVE"
        return uuid.UUID(response.json()["id"])


@pytest.fixture
async def fleet(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory, txt: FakeTxt, settings: Settings
) -> Fleet:
    owner = await make_user(db, app.state.passwords, "admin@acme.test")
    org = await make_org(db, slug="acme", created_by=owner, members={owner: OrgRole.ADMIN})
    await make_verified_domain(db, organization_id=org, fqdn="acme.example", created_by=owner)
    project = await make_project(db, organization_id=org, created_by=owner)
    admin = client_factory()
    await login(admin, "admin@acme.test")
    return Fleet(app, org, project, admin, FakeServer(), Resolver(), txt, settings)


async def make_due(db: AsyncSession, *monitor_ids: uuid.UUID) -> None:
    await db.execute(
        update(MonitorSchedule)
        .where(MonitorSchedule.monitor_id.in_(monitor_ids))
        .values(next_due_at=clock.now() - timedelta(seconds=1))
    )
    await db.commit()


async def run_once(worker: Worker) -> int:
    jobs = await worker.claim_and_start()
    await worker.drain(30)
    return len(jobs)


async def measurements(db: AsyncSession, monitor_id: uuid.UUID) -> list[Measurement]:
    db.expire_all()
    rows = await db.scalars(
        select(Measurement)
        .where(Measurement.monitor_id == monitor_id)
        .order_by(Measurement.observed_at)
    )
    return list(rows)


async def health(db: AsyncSession, monitor_id: uuid.UUID) -> MonitorHealth:
    db.expire_all()
    row = await db.get(MonitorHealth, monitor_id)
    assert row is not None
    return row


async def schedule(db: AsyncSession, monitor_id: uuid.UUID) -> MonitorSchedule:
    db.expire_all()
    row = await db.get(MonitorSchedule, monitor_id)
    assert row is not None
    return row


async def test_due_monitor_is_checked_and_rescheduled(fleet: Fleet, db: AsyncSession) -> None:
    monitor_id = await fleet.monitor()
    await make_due(db, monitor_id)
    before = (await schedule(db, monitor_id)).next_due_at
    assert await run_once(fleet.worker()) == 1
    [measurement] = await measurements(db, monitor_id)
    assert (measurement.result, measurement.trigger, measurement.http_status) == (
        "PASS",
        "SCHEDULED",
        200,
    )
    assert measurement.organization_id == fleet.org
    assert fleet.server.connections == [(PUBLIC, 443)]
    assert "Host: api.acme.example" in fleet.server.requests[0].decode()
    after = await schedule(db, monitor_id)
    assert after.next_due_at == before + timedelta(seconds=60)
    assert after.lease_until is None and after.current_job_id is None
    assert (await health(db, monitor_id)).consecutive_successes == 1
    assert await run_once(fleet.worker()) == 0  # not due again yet


@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        ({}, "PASS"),
        ({"latency_threshold_ms": 1, "delay": 0.05}, "SLOW"),
        ({"response": b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n"}, "FAIL"),
        ({"answers": ["169.254.169.254"]}, "BLOCKED"),
        ({"connect_error": RuntimeError("probe bug")}, "INCONCLUSIVE"),
    ],
)
async def test_all_five_classifications_and_counter_eligibility(
    fleet: Fleet, db: AsyncSession, setup: dict[str, object], expected: str
) -> None:
    extra: dict[str, Any] = (
        {"latency_threshold_ms": setup["latency_threshold_ms"]}
        if "latency_threshold_ms" in setup
        else {}
    )
    monitor_id = await fleet.monitor(**extra)
    if "response" in setup:
        fleet.server.response = setup["response"]  # type: ignore[assignment]
    if "delay" in setup:
        fleet.server.response_delay = setup["delay"]  # type: ignore[assignment]
    if "answers" in setup:
        fleet.resolver.answers["api.acme.example"] = setup["answers"]  # type: ignore[assignment]
    if "connect_error" in setup:
        fleet.server.connect_error = setup["connect_error"]  # type: ignore[assignment]
    await make_due(db, monitor_id)
    await run_once(fleet.worker())
    [measurement] = await measurements(db, monitor_id)
    assert measurement.result == expected
    counters = await health(db, monitor_id)
    eligible = expected in ("PASS", "SLOW", "FAIL")
    assert (counters.last_measurement_id is not None) == eligible
    if expected == "FAIL":
        assert counters.consecutive_failures == 1
    elif expected in ("PASS", "SLOW"):
        assert counters.consecutive_successes == 1
        assert counters.consecutive_slow == (1 if expected == "SLOW" else 0)
    else:
        assert (counters.consecutive_failures, counters.consecutive_successes) == (0, 0)
    assert counters.consecutive_blocked == (1 if expected == "BLOCKED" else 0)
    if expected == "BLOCKED":
        assert fleet.server.connections == []  # never connected to the metadata address


async def test_three_blocked_results_auto_pause(fleet: Fleet, db: AsyncSession) -> None:
    monitor_id = await fleet.monitor()
    fleet.resolver.answers["api.acme.example"] = ["10.0.0.8"]
    for _ in range(3):
        await make_due(db, monitor_id)
        await run_once(fleet.worker())
    db.expire_all()
    monitor = await db.get(Monitor, monitor_id)
    assert monitor is not None
    assert (monitor.lifecycle, monitor.paused_reason) == ("PAUSED", "POLICY_BLOCKED")
    events = (await fleet.admin.get(fleet.url("/audit"))).json()
    assert any(e["action"] == "system.monitor_auto_paused" for e in events)
    await make_due(db, monitor_id)
    assert await run_once(fleet.worker()) == 0


async def test_manual_check_never_changes_health_or_schedule(
    fleet: Fleet, db: AsyncSession
) -> None:
    monitor_id = await fleet.monitor()
    await db.execute(
        update(MonitorSchedule)
        .where(MonitorSchedule.monitor_id == monitor_id)
        .values(next_due_at=clock.now() + timedelta(hours=1))
    )
    await db.commit()
    fleet.server.response = b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n"
    queued = await fleet.admin.post(
        fleet.url(f"/monitors/{monitor_id}/check-now"), headers=csrf(fleet.admin)
    )
    assert queued.status_code == 202
    due_before = (await schedule(db, monitor_id)).next_due_at
    assert await run_once(fleet.worker()) == 1
    [measurement] = await measurements(db, monitor_id)
    assert (measurement.trigger, measurement.result) == ("MANUAL", "FAIL")
    counters = await health(db, monitor_id)
    assert (counters.consecutive_failures, counters.last_measurement_id) == (0, None)
    after = await schedule(db, monitor_id)
    assert after.next_due_at == due_before
    assert after.manual_check_requested_at is None


async def test_concurrent_workers_never_claim_the_same_monitor(
    fleet: Fleet, db: AsyncSession
) -> None:
    hosts = [f"m{i}.acme.example" for i in range(12)]
    monitor_ids = [await fleet.monitor(host) for host in hosts]
    await make_due(db, *monitor_ids)

    async def claim() -> list[uuid.UUID]:
        async with fleet.app.state.sessionmaker() as session:
            jobs = await claim_jobs(
                session,
                worker_id=f"w-{uuid.uuid4().hex[:6]}",
                capacity=Capacity(50, 50, 50, Counter(), Counter()),
                now=clock.now(),
                batch=50,
            )
        return [job.monitor_id for job in jobs]

    results = await asyncio.gather(*(claim() for _ in range(4)))
    claimed = [m for result in results for m in result]
    assert len(claimed) == len(set(claimed)) == 12


async def test_expired_lease_is_reclaimed_and_late_completion_discarded(
    fleet: Fleet, db: AsyncSession, frozen_clock: FrozenClock
) -> None:
    monitor_id = await fleet.monitor()
    await make_due(db, monitor_id)
    capacity = Capacity(5, 5, 5, Counter(), Counter())
    async with fleet.app.state.sessionmaker() as session:
        [crashed] = await claim_jobs(
            session, worker_id="crashed", capacity=capacity, now=clock.now(), batch=5
        )
    async with fleet.app.state.sessionmaker() as session:
        assert (
            await claim_jobs(
                session, worker_id="other", capacity=capacity, now=clock.now(), batch=5
            )
            == []
        )

    frozen_clock.advance(seconds=(crashed.lease_until - clock.now()).total_seconds() + 1)
    async with fleet.app.state.sessionmaker() as session:
        [reclaimed] = await claim_jobs(
            session, worker_id="rescuer", capacity=capacity, now=clock.now(), batch=5
        )
    assert reclaimed.monitor_id == monitor_id and reclaimed.job_id != crashed.job_id

    from sentinelops.probes.http.engine import CheckOutcome

    ok = CheckOutcome("PASS", http_status=200, elapsed_ms=10)
    async with fleet.app.state.sessionmaker() as session:
        late = await complete_job(session, crashed, ok, observed_at=clock.now(), now=clock.now())
    async with fleet.app.state.sessionmaker() as session:
        fresh = await complete_job(session, reclaimed, ok, observed_at=clock.now(), now=clock.now())
    async with fleet.app.state.sessionmaker() as session:
        replay = await complete_job(
            session, reclaimed, ok, observed_at=clock.now(), now=clock.now()
        )
    assert (late, fresh, replay) == ("stale", "recorded", "stale")
    assert len(await measurements(db, monitor_id)) == 1


async def test_pause_or_suspension_during_a_check_discards_its_result(
    fleet: Fleet, db: AsyncSession
) -> None:
    paused_id = await fleet.monitor("p.acme.example")
    suspended_id = await fleet.monitor("s.acme.example")
    await make_due(db, paused_id, suspended_id)
    fleet.server.response_delay = 0.3
    worker = fleet.worker()
    assert len(await worker.claim_and_start()) == 2
    await fleet.admin.post(fleet.url(f"/monitors/{paused_id}/pause"), headers=csrf(fleet.admin))
    from sentinelops.catalog.eligibility import bump_organization_generations

    await db.execute(
        update(Organization)
        .where(Organization.id == fleet.org)
        .values(status="SUSPENDED", suspended_at=clock.now())
    )
    await bump_organization_generations(db, fleet.org)
    await db.commit()
    await worker.drain(10)
    assert await measurements(db, paused_id) == []
    assert await measurements(db, suspended_id) == []
    await make_due(db, suspended_id)
    assert await run_once(fleet.worker()) == 0  # suspended organizations are never claimed


async def test_platform_suspension_and_activation_hooks(
    fleet: Fleet, db: AsyncSession, client_factory: ClientFactory
) -> None:
    monitor_id = await fleet.monitor()
    await make_due(db, monitor_id)
    await run_once(fleet.worker())
    assert (await health(db, monitor_id)).consecutive_successes == 1
    await make_user(db, fleet.app.state.passwords, "root@example.test", platform_admin=True)
    admin = client_factory()
    await login(admin, "root@example.test")
    base = f"/api/admin/organizations/{fleet.org}"
    await admin.post(f"{base}/suspend", json={"reason": "Fictional review"}, headers=csrf(admin))
    await make_due(db, monitor_id)
    assert await run_once(fleet.worker()) == 0
    await admin.post(f"{base}/activate", headers=csrf(admin))
    assert (await health(db, monitor_id)).consecutive_successes == 0  # health reset to UNKNOWN
    assert await run_once(fleet.worker()) == 1


async def test_unverified_domain_is_caught_before_the_check(fleet: Fleet, db: AsyncSession) -> None:
    monitor_id = await fleet.monitor()
    await db.execute(update(VerifiedDomain).values(status=DomainStatus.REVOKED))
    await db.commit()
    await make_due(db, monitor_id)
    assert await run_once(fleet.worker()) == 0
    assert fleet.resolver.calls == []
    db.expire_all()
    monitor = await db.get(Monitor, monitor_id)
    assert monitor is not None
    assert (monitor.lifecycle, monitor.attention_reason) == ("DRAFT", "DOMAIN_UNVERIFIED")


async def test_concurrency_caps_per_organization_and_host(fleet: Fleet, db: AsyncSession) -> None:
    ids = [await fleet.monitor(f"h{i}.acme.example") for i in range(5)]
    await make_due(db, *ids)
    fleet.server.response_delay = 0.2
    worker = fleet.worker(worker_org_concurrency=2)
    assert len(await worker.claim_and_start()) == 2
    assert len(await worker.claim_and_start()) == 0  # org cap reached while in flight
    await worker.drain(10)

    same_host = [await fleet.monitor("shared.acme.example") for _ in range(3)]
    await make_due(db, *same_host)
    host_worker = fleet.worker(worker_host_concurrency=1)
    jobs = await host_worker.claim_and_start()
    assert sum(1 for j in jobs if j.hostname == "shared.acme.example") == 1
    await host_worker.drain(10)


async def test_missed_slots_skip_to_the_next_future_slot(fleet: Fleet, db: AsyncSession) -> None:
    monitor_id = await fleet.monitor()
    await db.execute(
        update(MonitorSchedule)
        .where(MonitorSchedule.monitor_id == monitor_id)
        .values(next_due_at=clock.now() - timedelta(minutes=10, seconds=30))
    )
    await db.commit()
    await run_once(fleet.worker())
    row = await schedule(db, monitor_id)
    assert row.next_due_at > clock.now()
    assert row.missed_slots == 10


async def test_graceful_shutdown_finishes_running_checks(fleet: Fleet, db: AsyncSession) -> None:
    monitor_id = await fleet.monitor()
    await make_due(db, monitor_id)
    fleet.server.response_delay = 0.3
    worker = fleet.worker(worker_idle_seconds=0.1)
    stop = asyncio.Event()
    task = asyncio.create_task(worker.run_forever(stop))
    for _ in range(50):
        if worker.in_flight:
            break
        await asyncio.sleep(0.02)
    stop.set()
    await asyncio.wait_for(task, 10)
    assert [m.result for m in await measurements(db, monitor_id)] == ["PASS"]
    async with fleet.app.state.sessionmaker() as session:
        beat = await session.get(WorkerHeartbeat, worker.worker_id)
    assert beat is not None and beat.kind == "WORKER"


async def test_idle_worker_sleeps_instead_of_polling(fleet: Fleet) -> None:
    worker = fleet.worker(worker_idle_seconds=7)
    assert await worker._seconds_until_due() == 7  # nothing scheduled
    await fleet.monitor()
    assert 0 < await worker._seconds_until_due() <= 7


async def test_timeouts_are_recorded_as_failures(fleet: Fleet, db: AsyncSession) -> None:
    monitor_id = await fleet.monitor(timeout_ms=3000)
    fleet.server.connect_error = httpcore.ConnectTimeout("timed out")
    await make_due(db, monitor_id)
    await run_once(fleet.worker())
    [measurement] = await measurements(db, monitor_id)
    assert (measurement.result, measurement.failure_category) == ("FAIL", "CONNECT_TIMEOUT")


async def test_worker_opens_and_resolves_an_outage_end_to_end(
    fleet: Fleet, db: AsyncSession, frozen_clock: FrozenClock
) -> None:
    """Real worker path with a fake transport: three 503s → OUTAGE, two 200s → resolved (AC-004)."""
    from sentinelops.incidents.models import Incident

    monitor_id = await fleet.monitor()
    fleet.server.response = b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n"
    worker = fleet.worker()
    for _ in range(3):
        frozen_clock.advance(seconds=60)
        await make_due(db, monitor_id)
        assert await run_once(worker) == 1
    db.expire_all()
    [incident] = list(await db.scalars(select(Incident).where(Incident.monitor_id == monitor_id)))
    assert (incident.type, incident.status) == ("OUTAGE", "OPEN")
    incident_id = incident.id
    assert (await health(db, monitor_id)).state == "DOWN"
    fleet.server.response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    for _ in range(2):
        frozen_clock.advance(seconds=60)
        await make_due(db, monitor_id)
        await run_once(worker)
    db.expire_all()
    resolved = await db.get(Incident, incident_id)
    assert resolved is not None and (resolved.status, resolved.resolution) == ("RESOLVED", "AUTO")


async def test_worker_maintenance_marks_stale_health(
    fleet: Fleet, db: AsyncSession, frozen_clock: FrozenClock
) -> None:
    monitor_id = await fleet.monitor()
    await make_due(db, monitor_id)
    worker = fleet.worker()
    await run_once(worker)
    assert (await health(db, monitor_id)).state == "UP"
    frozen_clock.advance(minutes=10)
    await worker.maintenance()
    assert (await health(db, monitor_id)).state == "UNKNOWN"
