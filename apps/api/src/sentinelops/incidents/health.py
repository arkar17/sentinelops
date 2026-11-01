"""Health and incident decisions as pure functions (02_TECHNICAL_ARCHITECTURE.md §6).

Inputs are normalized results (FR-EXT-002), never HTTPX objects. Only scheduled PASS/SLOW/FAIL
results reach this module; BLOCKED, INCONCLUSIVE and MANUAL results never do (FR-MON-012).

Health:
- ``UNKNOWN → UP`` on the first PASS or SLOW. While an OUTAGE incident is still active (health was
  reset by staleness, pause/resume, edit or activation), recovery instead needs
  ``recovery_threshold`` consecutive PASS/SLOW, the same evidence as ``DOWN → UP``.
- ``UP → DEGRADED`` after ``failure_threshold`` consecutive SLOW;
  ``DEGRADED → UP`` after ``recovery_threshold`` consecutive PASS.
- ``UNKNOWN/UP/DEGRADED → DOWN`` after ``failure_threshold`` consecutive FAIL;
  ``DOWN → UP`` after ``recovery_threshold`` consecutive PASS/SLOW.
- At most one transition per result.

Incidents: OUTAGE opens on entering DOWN and resolves when health becomes available again.
TLS_EXPIRY opens when the observed certificate has less than ``tls_warn_days`` of validity left
and resolves when an observed certificate has at least that much.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum


class Health(StrEnum):
    UNKNOWN = "UNKNOWN"
    UP = "UP"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"


CONCLUSIVE = frozenset({"PASS", "SLOW", "FAIL"})
AVAILABLE = frozenset({Health.UP, Health.DEGRADED})


@dataclass(frozen=True)
class Counters:
    failures: int = 0
    successes: int = 0  # PASS or SLOW
    passes: int = 0
    slow: int = 0


@dataclass(frozen=True)
class Step:
    previous: Health
    state: Health
    counters: Counters

    @property
    def changed(self) -> bool:
        return self.previous is not self.state


def count(counters: Counters, result: str) -> Counters:
    if result == "FAIL":
        return Counters(failures=counters.failures + 1)
    if result == "PASS":
        return Counters(successes=counters.successes + 1, passes=counters.passes + 1)
    if result == "SLOW":
        return Counters(successes=counters.successes + 1, slow=counters.slow + 1)
    raise ValueError(f"{result!r} does not drive health")


def step(
    state: Health,
    counters: Counters,
    result: str,
    *,
    failure_threshold: int,
    recovery_threshold: int,
    outage_active: bool,
) -> Step:
    c = count(counters, result)
    new = state
    if state is not Health.DOWN and c.failures >= failure_threshold:
        new = Health.DOWN
    elif state is Health.DOWN:
        if c.successes >= recovery_threshold:
            new = Health.UP
    elif state is Health.UNKNOWN:
        if c.successes >= (recovery_threshold if outage_active else 1):
            new = Health.UP
    elif state is Health.UP:
        if c.slow >= failure_threshold:
            new = Health.DEGRADED
    elif c.passes >= recovery_threshold:  # DEGRADED
        new = Health.UP
    return Step(state, new, c)


def outage_action(after: Step, *, outage_active: bool) -> str | None:
    """ "open", "resolve" or None for the OUTAGE incident."""
    if after.state is Health.DOWN and not outage_active:
        return "open"
    if after.state in AVAILABLE and outage_active:
        return "resolve"
    return None


def tls_remaining(not_after: datetime, observed_at: datetime) -> timedelta:
    return not_after - observed_at


def tls_action(
    not_after: datetime | None, observed_at: datetime, *, warn_days: int, tls_active: bool
) -> str | None:
    """Missing certificate data (HTTP monitor, TLS failure, no response) changes nothing."""
    if not_after is None:
        return None
    below = tls_remaining(not_after, observed_at) < timedelta(days=warn_days)
    if below and not tls_active:
        return "open"
    if not below and tls_active:
        return "resolve"
    return None
