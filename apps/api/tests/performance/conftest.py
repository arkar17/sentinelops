"""Performance tests reuse the guarded integration harness unchanged: the same disposable
``sentinelops_test`` checks (local host, exact name, disposable marker, approved migration chain)
run before anything is migrated or seeded, and every test starts from the same reset."""

from tests.integration.conftest import (
    app,
    client_factory,
    db,
    mailer,
    owner_engine,
    secret_key,
    settings,
    test_database,
    txt,
)

__all__ = [
    "app",
    "client_factory",
    "db",
    "mailer",
    "owner_engine",
    "secret_key",
    "settings",
    "test_database",
    "txt",
]
