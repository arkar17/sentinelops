"""Report windows (timezones, DST), coverage arithmetic and CSV escaping without a database."""

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest

from sentinelops.errors import AppError
from sentinelops.measurements.reports import MonitorInfo, Stats, expected_slots, resolve_window
from sentinelops.measurements.routes import csv_cell

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)


def test_presets_end_now_and_choose_buckets() -> None:
    day = resolve_window("24h", None, None, "UTC", NOW)
    assert day.end - day.start == timedelta(hours=24) and day.end > NOW
    assert (day.bucket, day.exact_latency) == ("hour", True)
    month = resolve_window("30d", None, None, "UTC", NOW)
    assert month.bucket == "day" and month.exact_latency is True


@pytest.mark.parametrize(
    ("day", "hours"),
    [
        (date(2026, 3, 8), 23),  # US spring forward
        (date(2025, 11, 2), 25),  # US fall back
        (date(2026, 6, 1), 24),
    ],
)
def test_custom_days_are_local_and_dst_aware(day: date, hours: int) -> None:
    window = resolve_window("custom", day, day, "America/New_York", NOW)
    assert window.end - window.start == timedelta(hours=hours)
    assert window.start.astimezone(UTC).hour in (4, 5)  # local midnight in New York


def test_half_hour_timezones_and_old_windows_are_approximate() -> None:
    window = resolve_window("custom", date(2025, 1, 1), date(2025, 1, 1), "Asia/Kolkata", NOW)
    assert (window.start.hour, window.start.minute) == (18, 30)  # 00:00 IST
    assert window.exact_latency is False  # beyond raw retention: rollup percentiles


def test_custom_end_is_capped_at_now() -> None:
    window = resolve_window("custom", date(2026, 10, 31), date(2026, 11, 2), "UTC", NOW)
    assert window.end <= NOW + timedelta(seconds=1)


@pytest.mark.parametrize(
    ("period", "start", "end"),
    [
        ("custom", None, None),
        ("custom", date(2026, 2, 1), date(2026, 1, 1)),
        ("custom", date(2024, 1, 1), date(2026, 1, 1)),
        ("custom", date(2027, 1, 1), date(2027, 1, 2)),
        ("90d", None, None),
    ],
)
def test_invalid_windows(period: str, start: date | None, end: date | None) -> None:
    with pytest.raises(AppError):
        resolve_window(period, start, end, "UTC", NOW)


def test_expected_slots_start_at_monitor_creation() -> None:
    window = resolve_window("24h", None, None, "UTC", NOW)
    info = MonitorInfo(
        uuid.uuid4(), "m", "h", uuid.uuid4(), "p", "ACTIVE", 300, NOW - timedelta(hours=2)
    )
    assert expected_slots(info, window) == 24
    old = MonitorInfo(
        uuid.uuid4(), "m", "h", uuid.uuid4(), "p", "ACTIVE", 60, NOW - timedelta(days=9)
    )
    assert expected_slots(old, window) == 1440


def test_stats_never_report_success_without_samples() -> None:
    empty = Stats(expected=100)
    assert (empty.uptime_pct, empty.coverage_pct, empty.missed) == (None, 0.0, 100)
    stats = Stats(conclusive=8, available=6, blocked=1, inconclusive=1, expected=20)
    assert (stats.uptime_pct, stats.coverage_pct, stats.missed) == (75.0, 40.0, 10)
    over = Stats(conclusive=12, available=12, expected=10)  # interval changed mid-window
    assert over.coverage_pct == 100.0 and over.missed == 0


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=SUM(A1:A2)", "'=SUM(A1:A2)"),
        ("+cmd", "'+cmd"),
        ("-2+3", "'-2+3"),
        ("@SUM(1)", "'@SUM(1)"),
        ("\tx", "'\tx"),
        ("Payments API", "Payments API"),
        (95.5, "95.5"),
        (None, ""),
    ],
)
def test_csv_cells_neutralize_formulas(value: object, expected: str) -> None:
    assert csv_cell(value) == expected
