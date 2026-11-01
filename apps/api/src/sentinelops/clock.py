"""Single source of the current time, so tests can control expiry deterministically.

Call as ``clock.now()`` (attribute access) so monkeypatching takes effect everywhere.
"""

from datetime import UTC, datetime


def now() -> datetime:
    return datetime.now(UTC)


def now_default() -> datetime:
    """Column default that resolves ``now`` at call time (respects test monkeypatching)."""
    return now()
