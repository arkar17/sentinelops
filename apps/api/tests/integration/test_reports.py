"""G6 reports, rollups, retention and dashboards (AC-013, AC-021, FR-UI-001/002/006, NFR-006).

Measurements are fictional rows inserted with fixed timestamps; the clock is frozen.
"""

import asyncio
import csv
import io
import json
import uuid
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.incidents.models import Incident
from sentinelops.measurements.models import HourlyMonitorRollup, Measurement
from sentinelops.measurements.rollups import apply_retention, hour_floor, rollup_range
from tests.integration.conftest import ClientFactory
from tests.integration.g5 import SECRET_QUERY, Tenant, tenant
from tests.integration.helpers import login, make_user

pytestmark = pytest.mark.integration
__all__ = ["tenant"]


@pytest.fixture
def t(tenant: Tenant) -> Tenant:
    return tenant


async def backdate_monitor(
    t: Tenant, created_at: datetime, monitor: uuid.UUID | None = None
) -> None:
    async with t.session() as s:
        await s.execute(
            text("UPDATE monitor SET created_at = :at WHERE id = :m"),
            {"at": created_at, "m": monitor or t.monitor},
        )
        await s.commit()


async def add(
    t: Tenant,
    at: datetime,
    result: str,
    elapsed: int | None = 100,
    *,
    trigger: str = "SCHEDULED",
    monitor: uuid.UUID | None = None,
    org: uuid.UUID | None = None,
    tls_days: int | None = None,
) -> None:
    async with t.session() as s:
        s.add(
            Measurement(
                id=uuid.uuid4(),
                organization_id=org or t.org,
                monitor_id=monitor or t.monitor,
                job_id=uuid.uuid4(),
                trigger=trigger,
                source_kind="HTTP_PROBE",
                schema_version=1,
                scheduled_for=at,
                observed_at=at,
                ingested_at=at,
                result=result,
                failure_category="HTTP_STATUS_MISMATCH" if result == "FAIL" else None,
                http_status=200 if result in ("PASS", "SLOW") else None,
                elapsed_ms=elapsed,
                attempt_count=1,
                tls_not_after=at + timedelta(days=tls_days) if tls_days is not None else None,
            )
        )
        await s.commit()


async def report(t: Tenant, query: str = "period=24h", client: Any = None) -> dict[str, Any]:
    response = await (client or t.admin).get(t.url(f"/reports?{query}"))
    assert response.status_code == 200, response.text
    return response.json()


# --- uptime, coverage, percentiles ----------------------------------------------------------------


async def test_uptime_and_coverage_follow_the_denominator_policy(t: Tenant) -> None:
    now = clock.now()
    await backdate_monitor(t, now - timedelta(days=2))
    base = now - timedelta(hours=3)
    plan = ["PASS"] * 10 + ["SLOW"] * 2 + ["FAIL"] * 3 + ["BLOCKED"] * 4 + ["INCONCLUSIVE"]
    for i, result in enumerate(plan):
        await add(t, base + timedelta(minutes=i), result)
    for i in range(2):  # check-now results never count
        await add(t, base + timedelta(minutes=30 + i), "FAIL", trigger="MANUAL")
    body = await report(t)
    s = body["summary"]
    assert (s["conclusive_samples"], s["available_samples"], s["failed_samples"]) == (15, 12, 3)
    assert (s["blocked_samples"], s["inconclusive_samples"]) == (4, 1)
    assert s["uptime_pct"] == 80.0
    assert s["expected_samples"] == 1440
    assert s["coverage_pct"] == round(100 * 15 / 1440, 2)
    assert s["missed_samples"] == 1440 - 20
    assert s["downtime_estimate_seconds"] == 180
    assert body["window"]["latency_method"] == "exact"
    [row] = body["monitors"]
    assert row["stats"]["uptime_pct"] == 80.0 and row["hostname"] == "api.acme.example"


async def test_no_conclusive_samples_means_unknown_uptime_not_success(t: Tenant) -> None:
    now = clock.now()
    await backdate_monitor(t, now - timedelta(hours=5))
    for i in range(5):
        await add(t, now - timedelta(minutes=10 + i), "BLOCKED")
    s = (await report(t))["summary"]
    assert s["uptime_pct"] is None
    assert s["coverage_pct"] == 0.0
    assert s["blocked_samples"] == 5


async def test_percentiles_use_nearest_rank_over_available_samples(t: Tenant) -> None:
    now = clock.now()
    await backdate_monitor(t, now - timedelta(days=1))
    for i in range(1, 101):
        await add(t, now - timedelta(minutes=200 - i), "PASS" if i % 10 else "SLOW", elapsed=i)
    await add(t, now - timedelta(minutes=5), "FAIL", elapsed=15000)  # timeouts do not skew latency
    s = (await report(t))["summary"]
    assert (s["latency_p50_ms"], s["latency_p95_ms"]) == (50, 95)


async def test_series_buckets_follow_the_organization_timezone(t: Tenant) -> None:
    async with t.session() as s:
        await s.execute(
            text("UPDATE organization SET timezone = 'Asia/Tokyo' WHERE id = :o"), {"o": t.org}
        )
        await s.commit()
    now = clock.now()
    await backdate_monitor(t, now - timedelta(days=10))
    for days in (1, 2, 3):
        await add(t, now - timedelta(days=days), "PASS")
    body = await report(t, "period=7d")
    assert body["window"]["bucket"] == "day" and body["window"]["timezone"] == "Asia/Tokyo"
    for point in body["series"]:
        local = datetime.fromisoformat(point["bucket_start"]).astimezone(ZoneInfo("Asia/Tokyo"))
        assert (local.hour, local.minute) == (0, 0)  # local midnight
    assert sum(p["conclusive_samples"] for p in body["series"]) == 3


# --- rollups and retention ------------------------------------------------------------------------


async def test_rollups_are_idempotent_and_match_raw_results(t: Tenant) -> None:
    now = clock.now()
    await backdate_monitor(t, now - timedelta(days=5))
    hour = hour_floor(now - timedelta(days=2))
    for i, result in enumerate(["PASS"] * 40 + ["FAIL"] * 10 + ["BLOCKED"] * 5):
        await add(t, hour + timedelta(seconds=60 * i), result, elapsed=10 + i)
    day = (hour - timedelta(hours=1)).date()
    query = f"period=custom&from={day}&to={(hour + timedelta(hours=1)).date()}"
    before = await report(t, query)
    for _ in range(2):
        async with t.session() as s:
            await rollup_range(s, hour, hour + timedelta(hours=1))
            await s.commit()
    async with t.session() as s:
        [row] = list(await s.scalars(select(HourlyMonitorRollup)))
    assert (row.conclusive_samples, row.available_samples, row.failed_samples) == (50, 40, 10)
    assert (row.blocked_samples, row.missed_slots) == (5, 5)
    assert row.downtime_seconds_est == 600
    assert (row.latency_p50_ms, row.latency_p95_ms) == (29, 47)
    after = await report(t, query)
    assert after["summary"] == before["summary"]


async def test_concurrent_rollup_runs_converge(t: Tenant) -> None:
    now = clock.now()
    hour = hour_floor(now - timedelta(hours=6))
    for i in range(30):
        await add(t, hour + timedelta(minutes=i), "PASS" if i % 3 else "FAIL")

    async def run() -> None:
        async with t.session() as s:
            await rollup_range(s, hour - timedelta(hours=2), hour + timedelta(hours=2))
            await s.commit()

    await asyncio.gather(*(run() for _ in range(5)))
    async with t.session() as s:
        rows = list(await s.scalars(select(HourlyMonitorRollup)))
    assert len(rows) == 1 and (rows[0].conclusive_samples, rows[0].failed_samples) == (30, 10)


async def test_retention_rolls_up_before_deleting_and_keeps_history(t: Tenant) -> None:
    now = clock.now()
    await backdate_monitor(t, now - timedelta(days=400))
    old = hour_floor(now - timedelta(days=31))
    for i in range(6):
        await add(t, old + timedelta(minutes=i), "PASS" if i < 4 else "FAIL")
    await add(t, old + timedelta(minutes=30), "FAIL", trigger="MANUAL")
    recent = now - timedelta(days=29)
    await add(t, recent, "PASS")
    await t.check("FAIL", "FAIL", "FAIL")  # an incident and notifications history to keep
    async with t.session() as s:
        s.add(
            HourlyMonitorRollup(
                organization_id=t.org,
                monitor_id=t.monitor,
                window_start=hour_floor(now - timedelta(days=370)),
                conclusive_samples=1,
                available_samples=1,
            )
        )
        await s.commit()
        incidents_before = await s.scalar(select(func.count()).select_from(Incident))
    async with t.session() as s:
        deleted = await apply_retention(s, now)
        await s.commit()
    assert deleted == 7  # six scheduled (now rolled up) + one manual
    async with t.session() as s:
        remaining = list(await s.scalars(select(Measurement.observed_at)))
        rollups = {r.window_start: r for r in await s.scalars(select(HourlyMonitorRollup))}
        assert await s.scalar(select(func.count()).select_from(Incident)) == incidents_before
    assert all(at >= now - timedelta(days=30) for at in remaining)
    assert old in rollups and rollups[old].conclusive_samples == 6
    assert hour_floor(now - timedelta(days=370)) not in rollups  # rollups kept 12 months only
    # Reports over expired raw data still use the rollups.
    query = f"period=custom&from={old.date()}&to={old.date()}"
    body = await report(t, query)
    assert body["summary"]["conclusive_samples"] == 6
    assert body["summary"]["uptime_pct"] == round(100 * 4 / 6, 3)
    assert body["window"]["latency_method"] == "approximate"
    async with t.session() as s:  # a second run finds nothing more to delete
        assert await apply_retention(s, now) == 0


# --- incidents, dashboard, availability -----------------------------------------------------------


async def test_incident_summary_and_monitor_availability(t: Tenant) -> None:
    await t.check("PASS", "FAIL", "FAIL", "FAIL", "PASS", "PASS")
    s = (await report(t))["summary"]
    assert (s["incidents_opened"], s["outage_incidents_opened"], s["incidents_resolved"]) == (
        1,
        1,
        1,
    )
    assert s["outage_incident_seconds"] == 120 and s["mean_resolution_seconds"] == 120
    availability = await t.viewer.get(t.url(f"/reports/monitors/{t.monitor}/availability"))
    assert availability.status_code == 200
    periods = availability.json()["periods"]
    assert set(periods) == {"24h", "7d", "30d"}
    assert periods["24h"]["conclusive_samples"] == 6 and periods["24h"]["uptime_pct"] == 50.0


async def test_dashboard_reports_real_counts(t: Tenant) -> None:
    await t.check("PASS", tls_days=5)
    await t.check("FAIL", "FAIL", "FAIL")
    response = await t.viewer.get(t.url("/dashboard"))
    assert response.status_code == 200
    d = response.json()
    assert d["monitors_by_lifecycle"]["ACTIVE"] == 1
    assert d["health"] == {"UP": 0, "DEGRADED": 0, "DOWN": 1, "UNKNOWN": 0}
    assert d["active_incidents_by_severity"] == {"CRITICAL": 1, "WARNING": 1}
    assert {i["type"] for i in d["recent_incidents"]} == {"OUTAGE", "TLS_EXPIRY"}
    assert d["results_24h"]["FAIL"] == 3 and d["results_24h"]["PASS"] == 1
    assert [x["days_remaining"] for x in d["tls_expiring"]] == [4]
    assert len(d["recent_checks"]) == 4
    assert d["summary_24h"]["uptime_pct"] == 25.0
    assert SECRET_QUERY not in response.text and "/health" not in response.text


# --- export ---------------------------------------------------------------------------------------


async def test_csv_export_neutralizes_formulas_and_is_not_cached(t: Tenant) -> None:
    async with t.session() as s:
        await s.execute(
            text("UPDATE monitor SET name = :n WHERE id = :m"),
            {"n": '=HYPERLINK("http://evil.example","x")', "m": t.monitor},
        )
        await s.commit()
    await t.check("PASS", "FAIL")
    response = await t.member.get(t.url("/reports/export.csv?period=24h"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert response.headers["cache-control"] == "no-store"
    assert "attachment" in response.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[1][0] == "monitor"
    assert rows[2][0].startswith("'=HYPERLINK")
    assert rows[-1][0] == "All monitors" and rows[-1][4] == "50.0"
    assert SECRET_QUERY not in response.text and "/health" not in response.text
    assert (await t.viewer.get(t.url("/reports/export.csv"))).status_code == 403  # RPT.export


async def test_invalid_ranges_are_rejected(t: Tenant) -> None:
    for query in (
        "period=custom",
        "period=custom&from=2026-02-01&to=2026-01-01",
        "period=custom&from=2020-01-01&to=2026-01-01",
        "period=custom&from=2999-01-01&to=2999-01-02",
        "period=1y",
    ):
        assert (await t.admin.get(t.url(f"/reports?{query}"))).status_code == 422, query


# --- isolation ------------------------------------------------------------------------------------


async def test_reports_are_tenant_scoped(t: Tenant) -> None:
    now = clock.now()
    await add(t, now - timedelta(minutes=3), "FAIL")
    for path in (
        "/dashboard",
        "/reports",
        "/reports/export.csv",
        f"/reports/monitors/{t.monitor}/availability",
        "/events",
    ):
        assert (await t.outsider.get(t.url(path))).status_code == 404, path
    other = f"/api/orgs/{t.other_org}"
    mine = await t.outsider.get(f"{other}/reports?project_id={t.project}")
    assert mine.json()["total_monitors"] == 0 and mine.json()["summary"]["conclusive_samples"] == 0
    foreign = await t.outsider.get(f"{other}/reports/monitors/{t.monitor}/availability")
    assert foreign.status_code == 404
    dashboard = (await t.outsider.get(f"{other}/dashboard")).json()
    assert dashboard["results_24h"]["FAIL"] == 0 and dashboard["recent_checks"] == []


async def test_platform_dashboard_is_aggregate_only(
    t: Tenant, client_factory: ClientFactory, db: AsyncSession
) -> None:
    await t.check("FAIL", "FAIL", "FAIL")
    await make_user(db, t.app.state.passwords, "root@platform.test", platform_admin=True)
    root = client_factory()
    await login(root, "root@platform.test")
    response = await root.get("/api/admin/dashboard")
    assert response.status_code == 200, response.text
    d = response.json()
    assert d["monitors_total"] == 1 and d["monitors_active"] == 1
    assert d["open_incidents_by_severity"]["CRITICAL"] == 1
    assert d["queue"]["checks_last_24h"] >= 3
    acme = next(o for o in d["organizations"] if o["slug"] == "acme")
    assert (acme["monitors_live"], acme["max_monitors"], acme["max_status_pages"]) == (1, 20, 3)
    for private in ("Payments API", "api.acme.example", SECRET_QUERY, "Outage detected", "/health"):
        assert private not in response.text, private
    assert (await t.admin.get("/api/admin/dashboard")).status_code in (403, 404)
    assert json.dumps(d)  # serializable aggregate payload


async def test_worker_rollup_task_is_serialized_and_safe(t: Tenant) -> None:
    from typing import cast

    from sentinelops.scheduler.loop import Worker

    now = clock.now()
    hour = hour_floor(now - timedelta(hours=2))
    for i in range(12):
        await add(t, hour + timedelta(minutes=5 * i), "PASS")
    workers = [
        Worker(
            t.app.state.sessionmaker,
            runner=cast(Any, None),
            settings=t.app.state.settings,
            txt_lookup=cast(Any, None),
        )
        for _ in range(3)
    ]
    await asyncio.gather(*(w.rollups(now) for w in workers))
    async with t.session() as s:
        [row] = list(await s.scalars(select(HourlyMonitorRollup)))
    assert row.conclusive_samples == 12 and row.window_start == hour
