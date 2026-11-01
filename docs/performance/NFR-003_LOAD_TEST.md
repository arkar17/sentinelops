# NFR-003 load test report

**Requirement (01_SRS.md §4, NFR-003):** 100 monitors across 10 organizations at 60 s intervals,
with ≥ 99% of scheduled checks starting within 10 s of due time. Not an SLA until load-tested.

**Result:** PASS on a local development host (two valid runs of each scenario, 1 Nov 2026).
This is evidence for the supported Phase 1 topology on local hardware with simulated probes; the
release checklist still requires a run on production-like hardware before any non-local
deployment.

## What is measured

| Term | Definition (source) |
|---|---|
| due_at | `monitor_schedule.next_due_at` when the job is claimed; carried by the job and stored as `measurement.scheduled_for` (trigger `SCHEDULED`) |
| started_at | `measurement.observed_at`, taken by `JobRunner.run` as its first action, before config load, decryption and the probe |
| start delay | started_at − due_at |
| probe start (cross-check) | when the probe's TLS handshake to the pinned address began, recorded by the simulated server |
| expected execution | every slot `first_due + k × 60 s` (fixed cadence, FR-SCH-002) inside the window, per monitor |
| missed | an expected slot with no measurement; counted as late |
| on-time % | executions with delay ≤ 10 s ÷ **expected** executions |

Both timestamps come from `clock.now()`, the product's only time source; nothing is frozen.

## Architecture under test

- **Harness:** `apps/api/tests/performance/test_nfr003_load.py` (pytest, markers `integration`
  and `performance`), reusing the guarded integration fixtures unchanged
  (`tests/performance/conftest.py`).
- **Database:** local PostgreSQL 18.4, database `sentinelops_test` only, passing the disposable-DB
  guard (local host, exact name, disposable marker, approved migration chain 0001–0009). The worker
  connects as the least-privilege app login role. Each scenario starts from the standard reset.
- **Seed:** 10 fictional organizations (`load-org-01…10`, verified domains `load-org-NN.example`),
  10 monitors each (`https://svcMM.load-org-NN.example/health`), 60 s interval, product defaults
  otherwise (timeout 10 s, retry_attempts 1). Created through `POST /api/orgs/{org}/monitors`, so
  schedules get the product's own initial jitter.
- **Worker:** ONE `Worker.run_forever` with default settings (concurrency 50, per-org 10,
  per-host 2, batch 20, idle 5 s), real claim/lease (`FOR UPDATE SKIP LOCKED`), real
  `JobRunner` (config load, AES-GCM decryption), real `run_check` (URL and destination-IP policy,
  pinned transport, production 1 s retry delay), real `complete_job` (measurement, health/incident
  engine, cadence), and the periodic maintenance (heartbeats, staleness, status snapshots, rollups).
  The worker's concurrency is observed by a `JobRunner` subclass that forwards unchanged.
- **Simulated network only:** a fake resolver answers a public address, and the probe's
  `ProbeEnvironment.inner_backend` seam is an in-memory server. No socket is opened, no host is
  contacted; every connection went to the pinned address on 443.
- **Pessimistic target mix, per organization:** svc01 refuses connections (CONNECT_ERROR, retried),
  svc02 hangs past the timeout (TIMEOUT, retried: holds a slot ~21 s), svc03 answers 503 (not
  retried), svc04 answers after 2.5 s, svc05–10 answer 200 in 50–400 ms. Three monitors per
  organization are DOWN, with open incidents, throughout.
- **Scenarios:** `jittered` (schedules as the product creates them) and `aligned` (all 100 monitors
  due at the same instant every minute: worst-case burst). Window 600 s each (10 cycles), plus 30 s
  settle; slots due before the worker started are excluded as warm-up (none occurred).
- **Host:** Apple silicon Mac (10 CPUs, macOS 26.4), Python 3.14.6, API app, worker and database
  on the same machine (the API lifespan shares the worker's event loop: conservative).

## Results

| Run | Scenario | Expected | Observed | Missed | p50 | p95 | p99 | Max | ≤ 10 s | Dup. slot / overlapping runs | Worker errors | Retries | Verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | jittered | 1000 | 1000 | 0 | 0.036 s | 0.062 s | 0.068 s | 0.085 s | 1000 (100.0%) | 0 / 0 | 0 | 213 | PASS |
| 1 | aligned | 1000 | 1000 | 0 | 0.282 s | 0.659 s | 0.709 s | 0.741 s | 1000 (100.0%) | 0 / 0 | 0 | 220 | PASS |
| 2 | jittered | — | — | — | — | — | — | — | — | — | — | — | **INVALID** (host slept, see below) |
| 2 | aligned | 1000 | 1000 | 0 | 0.281 s | 0.663 s | 0.718 s | 0.789 s | 1000 (100.0%) | 0 / 0 | 0 | 220 | PASS |
| 3 | jittered | 1000 | 1000 | 0 | 0.036 s | 0.064 s | 0.069 s | 0.080 s | 1000 (100.0%) | 0 / 0 | 0 | 211 | PASS |
| 3 | aligned | 1000 | 1000 | 0 | 0.276 s | 0.666 s | 0.710 s | 0.763 s | 1000 (100.0%) | 0 / 0 | 0 | 220 | PASS |

In every valid run: 0 off-grid executions, 0 skipped slots (`missed_slots`), all run statuses
`recorded` (no `stale`, `duplicate` or crash), 0 worker warnings or errors, probe start ≤ 0.8 s
after due. Peak in-flight checks: jittered 8–10 (≤ 4 per organization); aligned 50 (the worker cap)
with 10 per organization (the org cap). Retries are probe retries of the CONNECT_ERROR/TIMEOUT
monitors (`attempt_count − 1`), counted over the whole run.

### Invalid run (run 2, jittered)

macOS entered Idle Sleep at 09:01:38 UTC for 637 s (`pmset -g log`); no check started between
09:01:39 and 09:12:14, so 720 slots were skipped and delays reached 648 s. This measured a suspended
host, not the scheduler; run 3 repeated both scenarios under `caffeinate` with no sleep.

It did expose one behaviour worth recording: after the wake, 5 monitors had a second execution
while their first was still in flight, and the 5 first executions completed as `stale` (0 duplicate
measurements; the job-id/generation fence rejected them). The likely mechanism: leases expire by
wall clock (`lease_until`), while in-flight probe timers use the monotonic clock, which does not
advance during macOS sleep, so expired leases were reclaimed while the original checks were still
running. This is the designed lease-reclaim path; a VM pause in production could trigger it too.
Recording stays correct; whether to also suppress the overlap is a follow-up decision, not part of
NFR-003.

## Follow-up reliability risk (open, not implemented)

**FR-RISK: overlapping executions after a host suspend.** Observed once (run 2, jittered): after
637 s of host sleep, 5 monitors had a second execution start while the first was still in flight.

- **Impact observed:** none on recorded data. All 5 first executions completed as `stale` and
  were rejected by the job-id/generation check; 0 duplicate measurements, 0 duplicate incident
  transitions. Each affected monitor did, however, send a second probe to its target while the
  first was still open, which briefly exceeds the intended one-check-per-monitor behaviour and can
  count twice against the per-host cap.
- **Likely cause (inferred, not proven):** `lease_until` is compared against wall-clock time,
  while in-flight checks are timed by the monotonic event-loop clock, which does not advance during
  macOS sleep. On wake the leases had expired and were reclaimed by the same worker while the
  original tasks were still running.
- **Where it can occur in production:** VM pause, live migration, container freeze, or a large
  forward wall-clock step on the worker host.
- **Status:** open follow-up for PO/architecture review. No code was changed. Possible directions
  (for decision, not approved): have the worker skip reclaiming monitors it still runs in process,
  or cancel in-flight checks whose lease has expired. Any change needs an IC/ADR entry and a
  reproducer test (e.g. a frozen-clock jump past `lease_until` with a check still in flight).

## Bottlenecks

None limits NFR-003 at this scale. In the aligned burst the start delay is bounded by the
worker cap (50 slots for 100 simultaneous checks: the second half waits for slots) and the claim
cadence (batch 20 per iteration, 50 ms minimum wait), giving a p99 of ~0.7 s. Nothing was tuned.

## Reproduce

```bash
# apps/api; disposable local database named exactly sentinelops_test (guarded)
SENTINELOPS_TEST_DATABASE_URL=postgresql+asyncpg://<owner>@127.0.0.1:5432/sentinelops_test \
SENTINELOPS_LOAD_TEST=1 SENTINELOPS_LOAD_DURATION_SECONDS=600 \
SENTINELOPS_LOAD_REPORT_DIR=<dir> caffeinate -dims uv run pytest tests/performance -s
```

Each scenario writes `executions.csv` (monitor, organization, due_at, started_at,
start_delay_seconds, probe start, result, attempts, ON_TIME/LATE/MISSED) and `summary.json`. The test
fails unless ≥ 99% of expected executions start within 10 s, with no duplicate or overlapping
execution, no off-grid or non-recorded run, no worker error, caps respected and no connection
other than the pinned address. Without `SENTINELOPS_LOAD_TEST=1` it is skipped (CI included).
