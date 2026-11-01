"""NFR-003 load test: 100 monitors across 10 organizations at 60 s intervals, with >= 99% of
scheduled checks starting within 10 s of their due time (01_SRS.md §4, G7 plan).

What runs is the production scheduling path, on the real clock, in ONE worker with the default
caps (concurrency 50, per organization 10, per host 2): ``Worker.run_forever`` claims due schedules
under leases (``FOR UPDATE SKIP LOCKED``) and runs its periodic maintenance, ``JobRunner`` loads and
decrypts each monitor's configuration and calls ``run_check`` (full URL and destination-IP policy,
pinned transport), and ``complete_job`` records the measurement, runs the health/incident engine
and advances the fixed cadence. Only the network is simulated: a fake resolver answers with a public
address and the probe's inner network backend (the ``ProbeEnvironment.inner_backend`` test seam) is
an in-memory server. No socket is opened and no host is contacted.

Timestamps (all from ``clock.now()``, the product's only time source; nothing is frozen):
- due_at: ``monitor_schedule.next_due_at`` when the job is claimed, carried by the job and stored
  as ``measurement.scheduled_for`` (trigger SCHEDULED).
- started_at: ``measurement.observed_at``, taken by ``JobRunner.run`` as its first action, before
  configuration loading and the probe. As a cross-check, the simulated server also records when
  the probe's TLS handshake to the pinned address began (probe_started_at).
- start delay: started_at - due_at. A slot of a monitor's fixed 60 s cadence inside the window
  without an execution is missed and counts as late.

Long-running (SENTINELOPS_LOAD_DURATION_SECONDS, default 600 per scenario), so it runs only with
SENTINELOPS_LOAD_TEST=1 against the guarded disposable database. A per-execution CSV and a JSON
summary are written to SENTINELOPS_LOAD_REPORT_DIR (default: pytest's tmp_path).
"""

import asyncio
import csv
import hashlib
import json
import logging
import math
import os
import platform
import sys
import uuid
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpcore
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.catalog.models import Monitor
from sentinelops.config import Settings
from sentinelops.measurements.models import Measurement
from sentinelops.probes.http.engine import ProbeEnvironment
from sentinelops.scheduler.loop import Worker
from sentinelops.scheduler.models import MonitorSchedule
from sentinelops.scheduler.runner import JobRunner
from sentinelops.scheduler.service import SCHEDULED, ClaimedJob
from sentinelops.tenancy.models import Organization, OrgRole
from tests.integration.conftest import ClientFactory, FakeTxt
from tests.integration.helpers import (
    csrf,
    login,
    make_org,
    make_project,
    make_user,
    make_verified_domain,
    monitor_body,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.performance,
    pytest.mark.skipif(
        os.environ.get("SENTINELOPS_LOAD_TEST") != "1",
        reason="NFR-003 load test runs only with SENTINELOPS_LOAD_TEST=1 (takes minutes)",
    ),
]

ORGS = 10
MONITORS_PER_ORG = 10
INTERVAL = timedelta(seconds=60)
THRESHOLD_SECONDS = 10.0
REQUIRED_ON_TIME = 0.99
DURATION_SECONDS = float(os.environ.get("SENTINELOPS_LOAD_DURATION_SECONDS", "600"))
SETTLE_SECONDS = 30.0  # after the window, so slots due at its end can start or show as missed
PUBLIC = "93.184.216.34"  # what the fake resolver answers; only the in-memory backend sees it
OPERATOR_EMAIL = "load-operator@sentinelops.test"  # fictional

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
UNAVAILABLE = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
HANG_SECONDS = 60.0  # longer than any allowed timeout


# --- simulated network (no sockets) ---


@dataclass
class SimulatedTargets:
    """Per-host behaviour, deliberately pessimistic (30% unhealthy). In every organization, with
    the default retry_attempts=1 and timeout 10 s:
    - svc01 refuses the connection (CONNECT_ERROR: retried after 1 s, then DOWN + incident);
    - svc02 hangs past the timeout (TIMEOUT: retried, so it holds a worker slot for ~21 s);
    - svc03 answers 503 (HTTP_STATUS_MISMATCH: not retried, DOWN + incident);
    - svc04 answers 200 after 2.5 s;
    - the others answer 200 in 50-400 ms (deterministic per host)."""

    tls_starts: dict[str, list[datetime]] = field(default_factory=dict[str, list[datetime]])
    connections: Counter[tuple[str, int]] = field(default_factory=Counter[tuple[str, int]])

    @staticmethod
    def refuses(hostname: str) -> bool:
        return hostname.startswith("svc01.")

    @staticmethod
    def response(hostname: str) -> tuple[float, bytes]:
        label = hostname.split(".", 1)[0]
        if label == "svc02":
            return HANG_SECONDS, OK
        if label == "svc03":
            return 0.2, UNAVAILABLE
        if label == "svc04":
            return 2.5, OK
        return 0.05 + hashlib.sha256(hostname.encode()).digest()[0] / 255 * 0.35, OK


class SimulatedStream(httpcore.AsyncNetworkStream):
    def __init__(self, targets: SimulatedTargets) -> None:
        self._targets = targets
        self._hostname = ""
        self._buffer = b""
        self._answered = False

    async def start_tls(
        self,
        ssl_context: Any,
        server_hostname: str | None = None,
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> httpcore.AsyncNetworkStream:
        self._hostname = server_hostname or ""
        self._targets.tls_starts.setdefault(self._hostname, []).append(clock.now())
        if self._targets.refuses(self._hostname):
            raise httpcore.ConnectError("simulated: connection refused")
        return self

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:  # noqa: ASYNC109
        return None

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:  # noqa: ASYNC109
        if not self._answered:
            self._answered = True
            delay, self._buffer = self._targets.response(self._hostname)
            await asyncio.sleep(delay)
        chunk, self._buffer = self._buffer[:max_bytes], self._buffer[max_bytes:]
        return chunk

    async def aclose(self) -> None:
        return None

    def get_extra_info(self, info: str) -> Any:
        return None


class SimulatedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, targets: SimulatedTargets) -> None:
        self.targets = targets

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.targets.connections[(host, port)] += 1
        return SimulatedStream(self.targets)

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


@dataclass
class PublicResolver:
    calls: int = 0

    async def __call__(self, hostname: str, port: int) -> Sequence[str]:
        self.calls += 1
        return [PUBLIC]


# --- observation (forwards to the real runner unchanged) ---


@dataclass
class TrackingRunner(JobRunner):
    """The real JobRunner, plus counters of concurrent executions per monitor/org and overall."""

    active: Counter[uuid.UUID] = field(default_factory=Counter[uuid.UUID])
    active_by_org: Counter[uuid.UUID] = field(default_factory=Counter[uuid.UUID])
    statuses: Counter[str] = field(default_factory=Counter[str])
    overlapping_runs: int = 0
    max_active_total: int = 0
    max_active_org: int = 0

    async def run(self, job: ClaimedJob) -> str:
        self.active[job.monitor_id] += 1
        self.active_by_org[job.organization_id] += 1
        if self.active[job.monitor_id] > 1:
            self.overlapping_runs += 1
        self.max_active_total = max(self.max_active_total, sum(self.active.values()))
        self.max_active_org = max(self.max_active_org, self.active_by_org[job.organization_id])
        status = "raised"
        try:
            status = await super().run(job)
            return status
        finally:
            self.statuses[status] += 1
            self.active[job.monitor_id] -= 1
            self.active_by_org[job.organization_id] -= 1


class LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


# --- seeding (fictional, through the real API) ---


@dataclass(frozen=True)
class SeededMonitor:
    monitor_id: uuid.UUID
    organization_id: uuid.UUID
    organization_slug: str
    hostname: str


async def seed(
    app: FastAPI, db: AsyncSession, client_factory: ClientFactory
) -> list[SeededMonitor]:
    """10 fictional organizations x 10 monitors (60 s), created via POST /monitors so schedules get
    the product's own initial jitter."""
    operator = await make_user(db, app.state.passwords, OPERATOR_EMAIL)
    orgs: list[tuple[uuid.UUID, str, uuid.UUID]] = []
    for n in range(1, ORGS + 1):
        slug = f"load-org-{n:02d}"
        org = await make_org(
            db,
            slug=slug,
            name=f"Load Org {n:02d} (fictional)",
            created_by=operator,
            members={operator: OrgRole.ADMIN},
        )
        await make_verified_domain(
            db, organization_id=org, fqdn=f"{slug}.example", created_by=operator
        )
        orgs.append((org, slug, await make_project(db, organization_id=org, created_by=operator)))
    client = client_factory()
    assert (await login(client, OPERATOR_EMAIL)).status_code == 200
    seeded: list[SeededMonitor] = []
    for org, slug, project in orgs:
        for m in range(1, MONITORS_PER_ORG + 1):
            hostname = f"svc{m:02d}.{slug}.example"
            body = monitor_body(
                project,
                url=f"https://{hostname}/health",
                name=f"Service {m:02d}",
                interval_seconds=int(INTERVAL.total_seconds()),
            )
            response = await client.post(
                f"/api/orgs/{org}/monitors", json=body, headers=csrf(client)
            )
            assert response.status_code == 201, response.text
            assert response.json()["lifecycle"] == "ACTIVE"
            seeded.append(SeededMonitor(uuid.UUID(response.json()["id"]), org, slug, hostname))
    return seeded


# --- analysis ---


def percentile(sorted_values: list[float], p: float) -> float:
    """Nearest-rank percentile."""
    if not sorted_values:
        return math.nan
    rank = max(1, math.ceil(p / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


def expected_slots(
    first_due: datetime, window_start: datetime, window_end: datetime
) -> list[datetime]:
    """Fixed cadence first_due + k*interval (FR-SCH-002), restricted to the window."""
    k = max(0, math.ceil((window_start - first_due) / INTERVAL))
    slots: list[datetime] = []
    due = first_due + k * INTERVAL
    while due <= window_end:
        slots.append(due)
        due += INTERVAL
    return slots


def due_of(measurement: Measurement) -> datetime:
    assert measurement.scheduled_for is not None  # always set for SCHEDULED checks
    return measurement.scheduled_for


def first_probe_start(starts: list[datetime], started_at: datetime) -> datetime | None:
    return next((t for t in starts if t >= started_at), None)


def iso(value: datetime | None) -> str:
    return value.isoformat() if value is not None else ""


async def run_scenario(
    scenario: str,
    *,
    aligned: bool,
    app: FastAPI,
    db: AsyncSession,
    client_factory: ClientFactory,
    txt: FakeTxt,
    settings: Settings,
    report_root: Path,
) -> dict[str, Any]:
    # Supported Phase 1 topology and default caps (IC-09); nothing is tuned for the test.
    assert settings.worker_concurrency == 50
    assert settings.worker_org_concurrency == 10
    assert settings.worker_host_concurrency == 2

    monitors = await seed(app, db, client_factory)
    assert len(monitors) == ORGS * MONITORS_PER_ORG
    assert len({m.organization_id for m in monitors}) == ORGS
    by_id = {m.monitor_id: m for m in monitors}
    assert set(await db.scalars(select(Monitor.interval_seconds))) == {60}

    if aligned:  # worst case: every monitor due at the same instant, every minute
        burst = clock.now() + timedelta(seconds=5)
        await db.execute(update(MonitorSchedule).values(next_due_at=burst))
        await db.commit()
    db.expire_all()
    first_due = {
        row.monitor_id: row.next_due_at for row in await db.scalars(select(MonitorSchedule))
    }

    targets = SimulatedTargets()
    resolver = PublicResolver()
    # Production retry delay (1 s) is kept: retries hold worker slots as they would in production.
    environment = ProbeEnvironment(resolver=resolver, inner_backend=SimulatedBackend(targets))
    runner = TrackingRunner(app.state.sessionmaker, app.state.secret_box, environment)
    worker = Worker(app.state.sessionmaker, runner, settings, txt)
    capture = LogCapture()
    sentinel_logger = logging.getLogger("sentinelops")
    sentinel_logger.addHandler(capture)
    stop = asyncio.Event()
    window_start = clock.now()
    window_end = window_start + timedelta(seconds=DURATION_SECONDS)
    task = asyncio.create_task(worker.run_forever(stop))
    try:
        await asyncio.sleep(DURATION_SECONDS + SETTLE_SECONDS)
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=settings.worker_shutdown_grace_seconds + 30)
        sentinel_logger.removeHandler(capture)

    db.expire_all()
    rows = list(
        await db.scalars(
            select(Measurement)
            .where(Measurement.trigger == SCHEDULED)
            .order_by(Measurement.scheduled_for)
        )
    )
    per_slot = Counter((m.monitor_id, due_of(m)) for m in rows)
    duplicate_slot_executions = sum(count - 1 for count in per_slot.values() if count > 1)
    executed = {(m.monitor_id, due_of(m)): m for m in rows}
    expected = {
        (monitor_id, due)
        for monitor_id, due0 in first_due.items()
        for due in expected_slots(due0, window_start, window_end)
    }
    in_window = [m for m in rows if window_start <= due_of(m) <= window_end]
    off_grid = [m for m in in_window if (m.monitor_id, due_of(m)) not in expected]
    warmup = sum(1 for m in rows if due_of(m) < window_start)
    after_window = sum(1 for m in rows if due_of(m) > window_end)
    org_slugs = {
        org_id: slug
        for org_id, slug in (await db.execute(select(Organization.id, Organization.slug))).all()
    }
    missed_slots_counter = await db.scalar(select(func.sum(MonitorSchedule.missed_slots)))
    pg_version = await db.scalar(text("SHOW server_version"))

    report_dir = report_root / f"{scenario}-{window_start:%Y%m%dT%H%M%SZ}"
    report_dir.mkdir(parents=True, exist_ok=True)
    delays: list[float] = []
    probe_delays: list[float] = []
    on_time = 0
    with (report_dir / "executions.csv").open("w", newline="") as handle:
        out = csv.writer(handle)
        out.writerow(
            [
                "monitor_id",
                "monitor_host",
                "organization_id",
                "organization_slug",
                "due_at",
                "started_at",
                "start_delay_seconds",
                "probe_started_at",
                "probe_start_delay_seconds",
                "result",
                "failure_category",
                "attempt_count",
                "status",
            ]
        )
        for monitor_id, due in sorted(expected, key=lambda key: (key[1], str(key[0]))):
            seeded = by_id[monitor_id]
            measurement = executed.get((monitor_id, due))
            if measurement is None:
                out.writerow(
                    [monitor_id, seeded.hostname, seeded.organization_id,
                     org_slugs[seeded.organization_id], iso(due), "", "", "", "", "", "", "",
                     "MISSED"]
                )  # fmt: skip
                continue
            delay = (measurement.observed_at - due).total_seconds()
            delays.append(delay)
            on_time += delay <= THRESHOLD_SECONDS
            probe_at = first_probe_start(
                targets.tls_starts.get(seeded.hostname, []), measurement.observed_at
            )
            probe_delay = (probe_at - due).total_seconds() if probe_at is not None else None
            if probe_delay is not None:
                probe_delays.append(probe_delay)
            out.writerow(
                [monitor_id, seeded.hostname, seeded.organization_id,
                 org_slugs[seeded.organization_id], iso(due), iso(measurement.observed_at),
                 f"{delay:.6f}", iso(probe_at),
                 f"{probe_delay:.6f}" if probe_delay is not None else "",
                 measurement.result, measurement.failure_category or "",
                 measurement.attempt_count,
                 "ON_TIME" if delay <= THRESHOLD_SECONDS else "LATE"]
            )  # fmt: skip

    delays.sort()
    probe_delays.sort()
    observed = len(expected) - sum(1 for key in expected if key not in executed)
    errors = [r for r in capture.records if r.levelno >= logging.ERROR]
    summary: dict[str, Any] = {
        "scenario": scenario,
        "window_start": iso(window_start),
        "window_end": iso(window_end),
        "duration_seconds": DURATION_SECONDS,
        "organizations": ORGS,
        "monitors": len(monitors),
        "interval_seconds": int(INTERVAL.total_seconds()),
        "worker_processes": 1,
        "worker_concurrency": settings.worker_concurrency,
        "worker_org_concurrency": settings.worker_org_concurrency,
        "worker_host_concurrency": settings.worker_host_concurrency,
        "worker_batch_size": settings.worker_batch_size,
        "expected_executions": len(expected),
        "observed_executions": observed,
        "missed_executions": len(expected) - observed,
        "warmup_executions_excluded": warmup,
        "after_window_executions_excluded": after_window,
        "off_grid_executions": len(off_grid),
        "start_delay_p50_seconds": percentile(delays, 50),
        "start_delay_p95_seconds": percentile(delays, 95),
        "start_delay_p99_seconds": percentile(delays, 99),
        "start_delay_max_seconds": delays[-1] if delays else math.nan,
        "start_delay_min_seconds": delays[0] if delays else math.nan,
        "probe_start_delay_p99_seconds": percentile(probe_delays, 99),
        "probe_start_delay_max_seconds": probe_delays[-1] if probe_delays else math.nan,
        "on_time_executions": on_time,
        "on_time_percent_of_expected": 100 * on_time / len(expected) if expected else math.nan,
        "late_executions": observed - on_time,
        "duplicate_slot_executions": duplicate_slot_executions,
        "overlapping_runs_same_monitor": runner.overlapping_runs,
        "max_in_flight_total": runner.max_active_total,
        "max_in_flight_one_org": runner.max_active_org,
        "run_statuses": dict(runner.statuses),
        "results": dict(Counter(m.result for m in rows)),
        "probe_retries": sum(m.attempt_count - 1 for m in rows),
        "failure_categories": dict(Counter(m.failure_category or "-" for m in rows)),
        "schedule_missed_slots": missed_slots_counter or 0,
        "worker_log_warnings": len(capture.records) - len(errors),
        "worker_log_errors": len(errors),
        "connections": {f"{host}:{port}": n for (host, port), n in targets.connections.items()},
        "resolver_calls": resolver.calls,
        "postgres_version": pg_version,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
    }
    summary["pass"] = bool(
        expected
        and on_time / len(expected) >= REQUIRED_ON_TIME
        and duplicate_slot_executions == 0
        and runner.overlapping_runs == 0
        and not off_grid
        and set(runner.statuses) <= {"recorded"}
        and not errors
        and runner.max_active_total <= settings.worker_concurrency
        and runner.max_active_org <= settings.worker_org_concurrency
        and set(targets.connections) <= {(PUBLIC, 443)}
    )
    (report_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    sys.stdout.write(f"\nNFR-003 {scenario}: {report_dir}\n{json.dumps(summary, indent=2)}\n")
    return summary


@pytest.fixture
def report_root(tmp_path: Path) -> Path:
    configured = os.environ.get("SENTINELOPS_LOAD_REPORT_DIR")
    return Path(configured) if configured else tmp_path


@pytest.mark.parametrize("scenario", ["jittered", "aligned"])
async def test_nfr003_scheduled_start_delay(
    scenario: str,
    app: FastAPI,
    db: AsyncSession,
    client_factory: ClientFactory,
    txt: FakeTxt,
    settings: Settings,
    report_root: Path,
) -> None:
    """jittered: schedules as the product creates them (initial jitter, FR-MON-005).
    aligned: all 100 monitors due at the same instant every minute (worst-case burst)."""
    summary = await run_scenario(
        scenario,
        aligned=scenario == "aligned",
        app=app,
        db=db,
        client_factory=client_factory,
        txt=txt,
        settings=settings,
        report_root=report_root,
    )
    assert summary["expected_executions"] >= ORGS * MONITORS_PER_ORG * 2  # several full cycles
    assert summary["pass"], json.dumps(summary, indent=2)
