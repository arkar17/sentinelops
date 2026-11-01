"""Unit tests for the disposable-database guard and the migration scope check (no DB needed)."""

import pytest

from tests.support.disposable_db import (
    REVISION_RANGES,
    REVISION_SCOPES,
    UnsafeDatabaseError,
    check_all_revisions,
    check_revision_scope,
    offline_upgrade_sql,
    verify_target,
)

SAFE_URL = "postgresql+asyncpg://postgres@127.0.0.1:5432/sentinelops_test"


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+asyncpg://postgres@db.internal:5432/sentinelops_test",
        "postgresql+asyncpg://postgres@10.0.0.5/sentinelops_test",
        "postgresql+asyncpg://postgres@127.0.0.1/sentinelops",
        "postgresql+asyncpg://postgres@127.0.0.1/sentinelops_dev",
        "postgresql+asyncpg://postgres@127.0.0.1/sentinelops_test_copy",
        "postgresql://postgres@127.0.0.1/sentinelops_test",
    ],
)
def test_guard_rejects_non_disposable_targets(url: str) -> None:
    with pytest.raises(UnsafeDatabaseError):
        verify_target(url)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_guard_accepts_local_sentinelops_test(host: str) -> None:
    verify_target(f"postgresql+asyncpg://postgres@{host}:5432/sentinelops_test")


def test_every_revision_stays_within_its_gate_scope() -> None:
    check_all_revisions(SAFE_URL)


def test_g1_revision_creates_only_the_app_role() -> None:
    sql = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0001"])
    assert "CREATE ROLE sentinelops_app NOLOGIN" in sql
    assert "GRANT SELECT, INSERT ON TABLE audit_event TO sentinelops_app" in sql


def test_g2_revision_adds_only_tenant_tables_and_audit_fk() -> None:
    sql = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0002"])
    assert "CREATE ROLE" not in sql
    assert "ALTER TABLE audit_event ADD CONSTRAINT" in sql
    assert "FOREIGN KEY(organization_id) REFERENCES organization (id)" in sql
    assert "FOREIGN KEY(selected_org_id, user_id) REFERENCES organization_member" in sql


@pytest.mark.parametrize(
    "extra",
    [
        "CREATE TABLE monitor (id uuid);",
        "DROP TABLE app_user;",
        "CREATE ROLE superuser_backdoor;",
        "GRANT ALL ON TABLE app_user TO public_reader;",
        "ALTER ROLE sentinelops_app PASSWORD 'x';",
        "ALTER TABLE app_user ADD COLUMN is_admin boolean;",
        "ALTER TABLE audit_event DROP CONSTRAINT ck_audit_event_scope_valid;",
        "DELETE FROM platform_admin;",
    ],
)
def test_scope_check_rejects_out_of_scope_sql(extra: str) -> None:
    sql = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0002"]) + "\n" + extra
    with pytest.raises(UnsafeDatabaseError):
        check_revision_scope(sql, REVISION_SCOPES["0002"])


def test_g3_revisions_add_only_catalog_and_measurement_tables() -> None:
    catalog = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0003"])
    measurements = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0004"])
    for sql in (catalog, measurements):
        assert "CREATE ROLE" not in sql
        assert "ALTER TABLE" not in sql
    assert (
        "FOREIGN KEY(organization_id, project_id) REFERENCES project (organization_id, id)"
        in catalog
    )
    assert (
        "FOREIGN KEY(organization_id, monitor_id) REFERENCES monitor (organization_id, id)"
        in measurements
    )
    assert "GRANT SELECT, INSERT ON TABLE measurement TO sentinelops_app" in measurements


def test_g1_scope_rejects_g2_tables() -> None:
    sql = offline_upgrade_sql(SAFE_URL, "base:0002")
    with pytest.raises(UnsafeDatabaseError):
        check_revision_scope(sql, REVISION_SCOPES["0001"])


def test_g4_revision_adds_only_incident_tables_and_the_pass_counter() -> None:
    sql = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0005"])
    assert "CREATE ROLE" not in sql
    assert "ALTER TABLE monitor_health ADD COLUMN consecutive_passes" in sql
    assert (
        "FOREIGN KEY(organization_id, assigned_user_id) "
        "REFERENCES organization_member (organization_id, user_id)"
    ) in sql
    assert (
        "FOREIGN KEY(organization_id, incident_id) REFERENCES incident (organization_id, id)"
    ) in sql
    assert "WHERE status <> 'RESOLVED'" in sql
    assert "GRANT SELECT, INSERT ON TABLE incident_event TO sentinelops_app" in sql
    assert "notification" not in sql


@pytest.mark.parametrize(
    "extra",
    [
        "CREATE TABLE notification_outbox (id uuid);",
        "ALTER TABLE monitor ADD COLUMN is_public boolean;",
        "ALTER TABLE monitor_health ADD COLUMN extra integer;",
        "ALTER TABLE monitor_health ALTER COLUMN state DROP NOT NULL;",
        "GRANT UPDATE, DELETE ON TABLE incident_event TO other_role;",
    ],
)
def test_g4_scope_rejects_out_of_scope_sql(extra: str) -> None:
    sql = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0005"]) + "\n" + extra
    with pytest.raises(UnsafeDatabaseError):
        check_revision_scope(sql, REVISION_SCOPES["0005"])


def test_g3_scope_rejects_g4_revision() -> None:
    with pytest.raises(UnsafeDatabaseError):
        check_revision_scope(
            offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0005"]), REVISION_SCOPES["0004"]
        )


def test_g5_revisions_add_only_notification_and_status_page_tables() -> None:
    notifications = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0006"])
    pages = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0007"])
    for sql in (notifications, pages):
        assert "CREATE ROLE" not in sql
        assert "ALTER TABLE" not in sql
    assert (
        "FOREIGN KEY(organization_id, user_id) "
        "REFERENCES organization_member (organization_id, user_id)"
    ) in notifications
    assert (
        "FOREIGN KEY(organization_id, channel_id) "
        "REFERENCES notification_channel (organization_id, id)"
    ) in notifications
    assert "GRANT SELECT, INSERT ON TABLE notification_delivery TO sentinelops_app" in notifications
    assert (
        "FOREIGN KEY(organization_id, monitor_id) REFERENCES monitor (organization_id, id)" in pages
    )
    assert "CREATE VIEW" not in pages  # platform views belong to G6


@pytest.mark.parametrize(
    "extra",
    [
        "CREATE TABLE smtp_server (id uuid);",
        "ALTER TABLE monitor ADD COLUMN is_public boolean;",
        "GRANT SELECT ON TABLE notification_channel TO public_reader;",
        "DROP TABLE incident;",
    ],
)
def test_g5_scope_rejects_out_of_scope_sql(extra: str) -> None:
    sql = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0006"]) + "\n" + extra
    with pytest.raises(UnsafeDatabaseError):
        check_revision_scope(sql, REVISION_SCOPES["0006"])


def test_g6_revision_adds_only_views_indexes_and_retention_grants() -> None:
    sql = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0008"])
    assert "CREATE TABLE" not in sql and "ALTER TABLE" not in sql
    for view in ("v_platform_org_summary", "v_platform_usage_daily", "v_platform_queue_health"):
        assert f"CREATE VIEW {view} AS" in sql
        assert f"GRANT SELECT ON TABLE {view} TO sentinelops_app" in sql
    assert "GRANT DELETE ON TABLE measurement TO sentinelops_app" in sql
    for forbidden in ("ciphertext", "display_url", "hostname", "title_sanitized", "details"):
        assert forbidden not in sql  # aggregate-only platform read model


@pytest.mark.parametrize(
    "extra",
    [
        "CREATE VIEW v_secret AS SELECT url_ciphertext FROM monitor;",
        "GRANT DELETE ON TABLE audit_event TO sentinelops_app;",
        "GRANT DELETE ON TABLE incident TO sentinelops_app;",
        "CREATE INDEX ix_x ON audit_event (at);",
        "GRANT UPDATE ON TABLE measurement TO sentinelops_app;",
    ],
)
def test_g6_scope_rejects_out_of_scope_sql(extra: str) -> None:
    sql = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0008"]) + "\n" + extra
    with pytest.raises(UnsafeDatabaseError):
        check_revision_scope(sql, REVISION_SCOPES["0008"])


def test_g7_revision_adds_only_mfa_tables_and_session_columns() -> None:
    sql = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0009"])
    assert "CREATE TABLE platform_admin_mfa" in sql
    assert "ALTER TABLE session ADD COLUMN mfa_pending" in sql
    assert "ALTER TABLE session ADD CONSTRAINT ck_session_mfa_pending_valid CHECK" in sql
    assert "CREATE ROLE" not in sql


@pytest.mark.parametrize(
    "extra",
    [
        "ALTER TABLE session ADD COLUMN is_admin boolean;",
        "ALTER TABLE app_user ADD CONSTRAINT ck_app_user_x CHECK (true);",
        "GRANT DELETE ON TABLE audit_event TO sentinelops_app;",
        "CREATE TABLE totp_plain (secret text);",
    ],
)
def test_g7_scope_rejects_out_of_scope_sql(extra: str) -> None:
    sql = offline_upgrade_sql(SAFE_URL, REVISION_RANGES["0009"]) + "\n" + extra
    with pytest.raises(UnsafeDatabaseError):
        check_revision_scope(sql, REVISION_SCOPES["0009"])
