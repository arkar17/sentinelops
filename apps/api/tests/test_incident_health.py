"""Pure health and incident decisions (02_TECHNICAL_ARCHITECTURE.md §6, FR-INC-001..003)."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

import pytest

from sentinelops.incidents.health import (
    Counters,
    Health,
    Step,
    count,
    outage_action,
    step,
    tls_action,
)

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)


def run(
    results: Iterable[str],
    *,
    start: Health = Health.UNKNOWN,
    ft: int = 3,
    rt: int = 2,
    outage_active: bool = False,
) -> list[Step]:
    """Feed results through the machine, tracking the outage incident like the engine does."""
    state, counters, steps = start, Counters(), []
    active = outage_active
    for result in results:
        s = step(
            state,
            counters,
            result,
            failure_threshold=ft,
            recovery_threshold=rt,
            outage_active=active,
        )
        action = outage_action(s, outage_active=active)
        active = {"open": True, "resolve": False}.get(action or "", active)
        steps.append(s)
        state, counters = s.state, s.counters
    return steps


def states(steps: list[Step]) -> list[str]:
    return [s.state.value for s in steps]


def test_counters_reset_on_opposite_results() -> None:
    c = count(count(count(Counters(), "FAIL"), "FAIL"), "SLOW")
    assert c == Counters(successes=1, slow=1)
    assert count(c, "PASS") == Counters(successes=2, passes=1)
    assert count(c, "FAIL") == Counters(failures=1)


@pytest.mark.parametrize("result", ["BLOCKED", "INCONCLUSIVE", "MANUAL"])
def test_non_conclusive_results_are_rejected(result: str) -> None:
    with pytest.raises(ValueError, match="does not drive health"):
        count(Counters(), result)


def test_first_success_from_unknown_is_up() -> None:
    assert states(run(["PASS"])) == ["UP"]
    assert states(run(["SLOW"])) == ["UP"]


def test_three_failures_go_down_exactly_on_the_threshold() -> None:
    steps = run(["FAIL", "FAIL", "FAIL"], start=Health.UP)
    assert states(steps) == ["UP", "UP", "DOWN"]
    assert [outage_action(s, outage_active=False) for s in steps] == [None, None, "open"]


def test_failure_streak_broken_by_success_does_not_go_down() -> None:
    assert states(run(["FAIL", "FAIL", "PASS", "FAIL", "FAIL"], start=Health.UP))[-1] == "UP"


def test_two_successes_recover_from_down_and_resolve() -> None:
    steps = run(["FAIL", "FAIL", "FAIL", "PASS", "SLOW"], start=Health.UP)
    assert states(steps) == ["UP", "UP", "DOWN", "DOWN", "UP"]
    assert outage_action(steps[-1], outage_active=True) == "resolve"


def test_flapping_inside_recovery_window_stays_down() -> None:
    steps = run(["FAIL"] * 3 + ["PASS", "FAIL", "PASS"], start=Health.UP)
    assert states(steps)[-3:] == ["DOWN", "DOWN", "DOWN"]


def test_slow_streak_degrades_and_passes_recover() -> None:
    steps = run(["SLOW", "SLOW", "SLOW", "PASS", "SLOW", "PASS", "PASS"], start=Health.UP)
    assert states(steps) == ["UP", "UP", "DEGRADED", "DEGRADED", "DEGRADED", "DEGRADED", "UP"]
    assert all(outage_action(s, outage_active=False) is None for s in steps)  # no DEGRADED incident


def test_degraded_monitor_can_go_down() -> None:
    steps = run(["SLOW"] * 3 + ["FAIL"] * 3, start=Health.UP)
    assert states(steps)[-1] == "DOWN"


def test_unknown_with_active_outage_needs_recovery_threshold() -> None:
    # Staleness or a pause/resume reset health while the outage incident stayed open.
    steps = run(["PASS", "PASS"], outage_active=True)
    assert states(steps) == ["UNKNOWN", "UP"]
    assert outage_action(steps[0], outage_active=True) is None
    assert outage_action(steps[1], outage_active=True) == "resolve"


def test_unknown_with_active_outage_failing_again_does_not_open_a_second() -> None:
    steps = run(["FAIL"] * 3, outage_active=True)
    assert states(steps)[-1] == "DOWN"
    assert outage_action(steps[-1], outage_active=True) is None


@pytest.mark.parametrize(("ft", "rt"), [(1, 1), (5, 3), (10, 10)])
def test_custom_thresholds_are_respected(ft: int, rt: int) -> None:
    steps = run(["FAIL"] * ft + ["PASS"] * rt, start=Health.UP, ft=ft, rt=rt)
    assert steps[ft - 1].state is Health.DOWN
    assert all(s.state is Health.DOWN for s in steps[ft - 1 : ft + rt - 1])
    assert steps[-1].state is Health.UP


def test_one_transition_per_result() -> None:
    s = step(
        Health.DOWN,
        Counters(),
        "PASS",
        failure_threshold=1,
        recovery_threshold=1,
        outage_active=True,
    )
    assert (s.previous, s.state) == (Health.DOWN, Health.UP)


# --- TLS expiry -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("days_left", "active", "expected"),
    [
        (30, False, None),
        (14, False, None),  # exactly at the threshold is not below it
        (13.9, False, "open"),
        (2, False, "open"),
        (5, True, None),  # already open: no duplicate
        (14, True, "resolve"),
        (90, True, "resolve"),
        (20, False, None),
    ],
)
def test_tls_threshold(days_left: float, active: bool, expected: str | None) -> None:
    not_after = NOW + timedelta(days=days_left)
    assert tls_action(not_after, NOW, warn_days=14, tls_active=active) == expected


@pytest.mark.parametrize("active", [True, False])
def test_missing_tls_data_changes_nothing(active: bool) -> None:
    assert tls_action(None, NOW, warn_days=14, tls_active=active) is None
