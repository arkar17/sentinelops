"""G6 platform read model and retention support.

Aggregate-only views for the SYSTEM_ADMIN console (03_DATABASE_DESIGN.md §5): per-organization
summary, daily usage and queue health. They expose counts and metadata only: never ciphertext,
hostnames, URLs, header or validation data, channel configuration, incident titles or events.
Retention (NFR-006, IC-12): the app role may DELETE raw measurements and expired hourly rollups,
with indexes for the batch deletes. No rows are created or deleted by this migration.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-31
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinelops_app"
VIEWS = ("v_platform_org_summary", "v_platform_usage_daily", "v_platform_queue_health")

ORG_SUMMARY = """
CREATE VIEW v_platform_org_summary AS
SELECT
    o.id AS organization_id,
    o.slug,
    o.name,
    o.status,
    o.created_at,
    ARRAY(
        SELECT u.email FROM organization_member om JOIN app_user u ON u.id = om.user_id
        WHERE om.organization_id = o.id AND om.role = 'ORG_OWNER' AND om.status = 'ACTIVE'
        ORDER BY u.email
    ) AS owner_emails,
    (SELECT count(*) FROM organization_member om
     WHERE om.organization_id = o.id AND om.status = 'ACTIVE') AS active_members,
    (SELECT count(*) FROM project p
     WHERE p.organization_id = o.id AND p.archived_at IS NULL) AS projects,
    (SELECT count(*) FROM monitor m
     WHERE m.organization_id = o.id AND m.lifecycle = 'ACTIVE') AS monitors_active,
    (SELECT count(*) FROM monitor m
     WHERE m.organization_id = o.id AND m.lifecycle = 'PAUSED') AS monitors_paused,
    (SELECT count(*) FROM monitor m
     WHERE m.organization_id = o.id AND m.lifecycle = 'DRAFT') AS monitors_draft,
    (SELECT count(*) FROM monitor m
     WHERE m.organization_id = o.id AND m.lifecycle = 'ARCHIVED') AS monitors_archived,
    (SELECT count(*) FROM status_page s WHERE s.organization_id = o.id) AS status_pages,
    (SELECT count(*) FROM notification_channel c WHERE c.organization_id = o.id) AS channels,
    (SELECT count(*) FROM incident i
     WHERE i.organization_id = o.id AND i.status <> 'RESOLVED'
       AND i.severity = 'CRITICAL') AS open_incidents_critical,
    (SELECT count(*) FROM incident i
     WHERE i.organization_id = o.id AND i.status <> 'RESOLVED'
       AND i.severity = 'WARNING') AS open_incidents_warning,
    COALESCE(l.max_monitors, ps.default_max_monitors) AS max_monitors,
    COALESCE(l.max_status_pages, ps.default_max_status_pages) AS max_status_pages,
    COALESCE(l.max_channels, ps.default_max_channels) AS max_channels
FROM organization o
CROSS JOIN platform_settings ps
LEFT JOIN organization_limit l ON l.organization_id = o.id
"""

USAGE_DAILY = """
CREATE VIEW v_platform_usage_daily AS
WITH checks AS (
    SELECT organization_id, (observed_at AT TIME ZONE 'UTC')::date AS day,
           count(*) AS checks,
           count(*) FILTER (WHERE result = 'PASS') AS pass,
           count(*) FILTER (WHERE result = 'SLOW') AS slow,
           count(*) FILTER (WHERE result = 'FAIL') AS fail,
           count(*) FILTER (WHERE result = 'BLOCKED') AS blocked,
           count(*) FILTER (WHERE result = 'INCONCLUSIVE') AS inconclusive
    FROM measurement GROUP BY 1, 2
),
opened AS (
    SELECT organization_id, (opened_at AT TIME ZONE 'UTC')::date AS day,
           count(*) AS incidents_opened
    FROM incident GROUP BY 1, 2
),
sent AS (
    SELECT organization_id, (attempted_at AT TIME ZONE 'UTC')::date AS day,
           count(*) FILTER (WHERE result_code = 'SENT') AS notifications_sent,
           count(*) FILTER (WHERE result_code <> 'SENT') AS notification_failures
    FROM notification_delivery GROUP BY 1, 2
)
SELECT organization_id, day,
       COALESCE(checks, 0) AS checks, COALESCE(pass, 0) AS pass, COALESCE(slow, 0) AS slow,
       COALESCE(fail, 0) AS fail, COALESCE(blocked, 0) AS blocked,
       COALESCE(inconclusive, 0) AS inconclusive,
       COALESCE(incidents_opened, 0) AS incidents_opened,
       COALESCE(notifications_sent, 0) AS notifications_sent,
       COALESCE(notification_failures, 0) AS notification_failures
FROM checks
FULL JOIN opened USING (organization_id, day)
FULL JOIN sent USING (organization_id, day)
"""

QUEUE_HEALTH = """
CREATE VIEW v_platform_queue_health AS
WITH due AS (
    SELECT s.next_due_at
    FROM monitor_schedule s
    JOIN monitor m ON m.organization_id = s.organization_id AND m.id = s.monitor_id
    JOIN organization o ON o.id = s.organization_id
    WHERE o.status = 'ACTIVE' AND m.lifecycle = 'ACTIVE' AND s.next_due_at <= now()
      AND (s.lease_until IS NULL OR s.lease_until < now())
)
SELECT
    (SELECT count(*) FROM due) AS due_backlog,
    (SELECT EXTRACT(EPOCH FROM now() - min(next_due_at)) FROM due) AS oldest_due_seconds,
    (SELECT count(*) FROM monitor_schedule WHERE lease_until > now()) AS checks_in_flight,
    (SELECT count(*) FROM measurement
     WHERE observed_at > now() - interval '15 minutes') AS checks_last_15m,
    (SELECT count(*) FROM measurement
     WHERE observed_at > now() - interval '24 hours') AS checks_last_24h,
    (SELECT count(*) FROM notification_outbox WHERE state = 'PENDING') AS outbox_pending,
    (SELECT count(*) FROM notification_outbox WHERE state = 'LEASED') AS outbox_leased,
    (SELECT EXTRACT(EPOCH FROM now() - min(next_attempt_at)) FROM notification_outbox
     WHERE state = 'PENDING' AND next_attempt_at <= now()) AS outbox_oldest_due_seconds,
    (SELECT count(*) FROM notification_outbox
     WHERE state = 'FAILED' AND created_at > now() - interval '24 hours') AS outbox_failed_24h
"""


def upgrade() -> None:
    op.execute(ORG_SUMMARY)
    op.execute(USAGE_DAILY)
    op.execute(QUEUE_HEALTH)
    for view in VIEWS:
        op.execute(f"GRANT SELECT ON TABLE {view} TO {APP_ROLE}")
    op.create_index("ix_measurement_observed_at", "measurement", ["observed_at"])
    op.create_index(
        "ix_hourly_monitor_rollup_window_start", "hourly_monitor_rollup", ["window_start"]
    )
    op.execute(f"GRANT DELETE ON TABLE measurement TO {APP_ROLE}")
    op.execute(f"GRANT DELETE ON TABLE hourly_monitor_rollup TO {APP_ROLE}")


def downgrade() -> None:
    op.execute(f"REVOKE DELETE ON TABLE hourly_monitor_rollup FROM {APP_ROLE}")
    op.execute(f"REVOKE DELETE ON TABLE measurement FROM {APP_ROLE}")
    op.drop_index("ix_hourly_monitor_rollup_window_start", table_name="hourly_monitor_rollup")
    op.drop_index("ix_measurement_observed_at", table_name="measurement")
    for view in reversed(VIEWS):
        op.execute(f"REVOKE ALL ON TABLE {view} FROM {APP_ROLE}")
        op.execute(f"DROP VIEW {view}")
