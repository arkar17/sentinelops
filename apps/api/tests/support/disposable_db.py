"""Safety guard for the disposable test database (G1 approval §4, G2 approval §6).

Before any migration is applied, the harness verifies that the target is a local database named
exactly ``sentinelops_test`` that is either empty or carries this project's disposable marker,
that the migration chain is the approved linear history, that each revision's SQL stays inside
its approved gate scope, and that earlier gates' revisions are applied first. Any failure stops
the run.
"""

import io
import re
from dataclasses import dataclass
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import make_url, text
from sqlalchemy.ext.asyncio import create_async_engine

ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1"})
REQUIRED_DATABASE = "sentinelops_test"
DISPOSABLE_MARKER = "sentinelops:disposable-test"
APP_ROLE = "sentinelops_app"
G1_TABLES = frozenset(
    {
        "app_user",
        "session",
        "auth_token",
        "auth_throttle",
        "platform_admin",
        "platform_admin_invitation",
        "platform_settings",
        "audit_event",
        "worker_heartbeat",
    }
)
FORBIDDEN_SQL = (
    r"\bDROP\s",
    r"\bTRUNCATE\b",
    r"\bDELETE\s+FROM\b",
    r"\bALTER\s+ROLE\b",
    r"\bSUPERUSER\b",
    r"\bPASSWORD\s+'",
)
G2_TABLES = frozenset(
    {
        "organization",
        "organization_limit",
        "organization_member",
        "org_invitation",
        "user_preference",
        "project",
    }
)

G3_CATALOG_TABLES = frozenset({"verified_domain", "monitor", "monitor_schedule", "monitor_health"})
G3_MEASUREMENT_TABLES = frozenset({"measurement", "hourly_monitor_rollup"})
G4_INCIDENT_TABLES = frozenset({"incident", "incident_event"})
G5_NOTIFICATION_TABLES = frozenset(
    {
        "notification_channel",
        "notification_channel_recipient",
        "notification_route",
        "notification_outbox",
        "notification_delivery",
    }
)
G5_STATUS_PAGE_TABLES = frozenset({"status_page", "status_page_monitor", "status_page_snapshot"})
G7_MFA_TABLES = frozenset({"platform_admin_mfa", "platform_admin_recovery_code"})
G6_PLATFORM_VIEWS = frozenset(
    {"v_platform_org_summary", "v_platform_usage_daily", "v_platform_queue_health"}
)


@dataclass(frozen=True)
class RevisionScope:
    tables: frozenset[str]
    roles: frozenset[str] = frozenset()
    # Existing tables a revision may alter, and only to add a foreign key.
    fk_additions: frozenset[str] = frozenset()
    # Existing (table, column) pairs a revision may add (ADD COLUMN only, never drop/alter).
    column_additions: frozenset[tuple[str, str]] = frozenset()
    # Read-only views a revision may create, and existing tables it may index.
    views: frozenset[str] = frozenset()
    index_additions: frozenset[str] = frozenset()
    # Extra privileges on existing tables, as (privilege, table).
    grant_additions: frozenset[tuple[str, str]] = frozenset()
    # Named CHECK constraints a revision may add to existing tables, as (table, name).
    check_additions: frozenset[tuple[str, str]] = frozenset()


REVISION_SCOPES = {
    "0001": RevisionScope(tables=G1_TABLES, roles=frozenset({APP_ROLE})),
    "0002": RevisionScope(tables=G2_TABLES, fk_additions=frozenset({"audit_event"})),
    "0003": RevisionScope(tables=G3_CATALOG_TABLES),
    "0004": RevisionScope(tables=G3_MEASUREMENT_TABLES),
    "0005": RevisionScope(
        tables=G4_INCIDENT_TABLES,
        column_additions=frozenset({("monitor_health", "consecutive_passes")}),
    ),
    "0006": RevisionScope(tables=G5_NOTIFICATION_TABLES),
    "0007": RevisionScope(tables=G5_STATUS_PAGE_TABLES),
    "0008": RevisionScope(
        tables=frozenset(),
        views=G6_PLATFORM_VIEWS,
        index_additions=frozenset({"measurement", "hourly_monitor_rollup"}),
        grant_additions=frozenset(
            {("DELETE", "measurement"), ("DELETE", "hourly_monitor_rollup")}
            | {("SELECT", view) for view in G6_PLATFORM_VIEWS}
        ),
    ),
    "0009": RevisionScope(
        tables=G7_MFA_TABLES,
        column_additions=frozenset({("session", "mfa_pending"), ("session", "mfa_failures")}),
        check_additions=frozenset({("session", "ck_session_mfa_pending_valid")}),
    ),
}
REVISION_RANGES = {
    "0001": "base:0001",
    "0002": "0001:0002",
    "0003": "0002:0003",
    "0004": "0003:0004",
    "0005": "0004:0005",
    "0006": "0005:0006",
    "0007": "0006:0007",
    "0008": "0007:0008",
    "0009": "0008:0009",
}
HEAD_REVISION = "0009"
API_ROOT = Path(__file__).resolve().parents[2]


class UnsafeDatabaseError(RuntimeError):
    """The target database failed a safety check; stop and request approval."""


def verify_target(url: str) -> None:
    parsed = make_url(url)
    if parsed.drivername != "postgresql+asyncpg":
        raise UnsafeDatabaseError(f"Unexpected driver {parsed.drivername!r}")
    if parsed.host not in ALLOWED_HOSTS:
        raise UnsafeDatabaseError(f"Host {parsed.host!r} is not localhost/127.0.0.1")
    if parsed.database != REQUIRED_DATABASE:
        raise UnsafeDatabaseError(f"Database {parsed.database!r} is not {REQUIRED_DATABASE!r}")


async def ensure_disposable(url: str) -> None:
    """Accept an empty database (and mark it) or one already carrying the disposable marker."""
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            user_tables = await conn.scalar(
                text(
                    "SELECT count(*) FROM pg_tables "
                    "WHERE schemaname NOT IN ('pg_catalog', 'information_schema')"
                )
            )
            marker = await conn.scalar(
                text(
                    "SELECT shobj_description(oid, 'pg_database') FROM pg_database "
                    "WHERE datname = current_database()"
                )
            )
            if marker == DISPOSABLE_MARKER:
                return
            if user_tables:
                raise UnsafeDatabaseError(
                    "sentinelops_test already contains tables and is not marked disposable"
                )
            await conn.execute(
                text(f"COMMENT ON DATABASE {REQUIRED_DATABASE} IS '{DISPOSABLE_MARKER}'")
            )
    finally:
        await engine.dispose()


def alembic_config(url: str, output: io.StringIO | None = None) -> Config:
    config = Config(str(API_ROOT / "alembic.ini"), output_buffer=output)
    config.set_main_option("script_location", str(API_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return config


def offline_upgrade_sql(url: str, revision_range: str = "head") -> str:
    buffer = io.StringIO()
    command.upgrade(alembic_config(url, buffer), revision_range, sql=True)
    return buffer.getvalue()


def check_revision_scope(sql: str, scope: RevisionScope) -> None:
    """A revision's upgrade SQL may only create its approved tables, roles, grants and FKs."""
    created = frozenset[str](re.findall(r"CREATE TABLE (\w+)", sql)) - {"alembic_version"}
    if created != scope.tables:
        raise UnsafeDatabaseError(
            f"Unexpected tables in migration: {sorted(created ^ scope.tables)}"
        )
    for pattern in FORBIDDEN_SQL:
        if re.search(pattern, sql, flags=re.IGNORECASE):
            raise UnsafeDatabaseError(f"Migration SQL matches forbidden pattern {pattern!r}")
    for role in re.findall(r"CREATE ROLE (\w+)", sql):
        if role not in scope.roles:
            raise UnsafeDatabaseError(f"Migration creates unexpected role {role!r}")
    for grantee in re.findall(r"GRANT [\w, ]+ ON (?:TABLE|SCHEMA) \w+ TO (\w+)", sql):
        if grantee != APP_ROLE:
            raise UnsafeDatabaseError(f"Migration grants to unexpected role {grantee!r}")
    for privileges, table in re.findall(r"GRANT ([\w, ]+) ON TABLE (\w+) TO", sql):
        if table in scope.tables:
            continue
        for privilege in (p.strip() for p in privileges.split(",")):
            if (privilege, table) not in scope.grant_additions:
                raise UnsafeDatabaseError(f"Unexpected grant {privilege} on {table!r}")
    views = frozenset[str](re.findall(r"CREATE VIEW (\w+)", sql))
    if views != scope.views:
        raise UnsafeDatabaseError(f"Unexpected views in migration: {sorted(views ^ scope.views)}")
    if re.search(r"CREATE (?:OR REPLACE )?(?:MATERIALIZED )?VIEW (?!\w+ AS)", sql):
        raise UnsafeDatabaseError("Unexpected view definition form")
    for table in re.findall(r"CREATE (?:UNIQUE )?INDEX \w+ ON (\w+)", sql):
        if table not in scope.tables and table not in scope.index_additions:
            raise UnsafeDatabaseError(f"Migration indexes existing table {table!r}")
    added = frozenset[tuple[str, str]](re.findall(r"ALTER TABLE (\w+) ADD COLUMN (\w+)", sql))
    if added - scope.column_additions:
        raise UnsafeDatabaseError(f"Unexpected column additions: {sorted(added)}")
    for table, change in re.findall(r"ALTER TABLE (\w+) (\w+(?: \w+)?)", sql):
        if table in scope.tables or change == "ADD COLUMN":  # additions checked above
            continue
        if change == "ADD CONSTRAINT" and any(t == table for t, _ in scope.check_additions):
            continue  # constraint names checked below
        if table not in scope.fk_additions or not change.startswith("ADD CONSTRAINT"):
            raise UnsafeDatabaseError(f"Migration alters existing table {table!r}: {change}")
    for fk_table, name in re.findall(
        r"ALTER TABLE (\w+) ADD CONSTRAINT (\w+) (?!FOREIGN KEY)", sql
    ):
        if (fk_table, name) in scope.check_additions:
            continue
        if fk_table not in scope.tables:
            raise UnsafeDatabaseError(f"Migration adds a non-FK constraint to {fk_table!r}")


def check_revision_chain(url: str) -> None:
    """The migration history is exactly the approved linear chain 0001 → … → head."""
    script = ScriptDirectory.from_config(alembic_config(url))
    chain = [rev.revision for rev in reversed(list(script.walk_revisions("base", "heads")))]
    if chain != list(REVISION_SCOPES):
        raise UnsafeDatabaseError(f"Unexpected migration chain: {chain}")


def check_all_revisions(url: str) -> None:
    check_revision_chain(url)
    for revision, revision_range in REVISION_RANGES.items():
        check_revision_scope(offline_upgrade_sql(url, revision_range), REVISION_SCOPES[revision])


async def current_revision(url: str) -> str | None:
    engine = create_async_engine(url)
    try:
        async with engine.connect() as conn:
            exists = await conn.scalar(text("SELECT to_regclass('public.alembic_version')"))
            if exists is None:
                return None
            return await conn.scalar(text("SELECT version_num FROM alembic_version"))
    finally:
        await engine.dispose()
