# SentinelOps — PostgreSQL Data Model · Baseline v1.0 · 31 Oct 2026

Requirements: `01_SRS.md`. Architecture: `02_TECHNICAL_ARCHITECTURE.md`. This document defines logical design. No migration or database is created by this document.

## 1. Conventions
- UUID primary keys (UUIDv7 generated in the application), `timestamptz` in UTC, `created_at` and `updated_at` on all rows, optimistic `version` on mutable configuration rows.
- Enumerations are `text` with `CHECK` constraints, which keeps Alembic migrations simple.
- **Tenant rule:** every organization-owned table has `organization_id NOT NULL`. Every organization-owned parent table has `UNIQUE (organization_id, id)`. Every child-to-parent reference within a tenant uses a **composite FK** `(organization_id, parent_id) → parent(organization_id, id)`. Nullable composite FKs rely on PostgreSQL's default `MATCH SIMPLE` (not checked when the optional column is NULL), which is intended.
- **Platform tables** (no `organization_id`): `app_user`, `session`, `auth_token`, `platform_admin`, `platform_admin_invitation`, `platform_settings`, `worker_heartbeat`.
- Secrets are stored only as `*_ciphertext` (AES-GCM, with associated data binding organization, table, row and field) plus `*_key_id`. No plaintext secret columns.
- Monitors are archived, never hard-deleted while history exists. Incident, measurement and audit history is retained and never cascade-deleted. FKs from history tables use `ON DELETE RESTRICT`.
- The application connects as role `sentinelops_app` (DML only, no DDL). Migrations run as `sentinelops_migrator`. `audit_event` grants INSERT/SELECT only to the app role.

## 2. Tables
### 2.1 Identity and platform
| Table | Columns | Constraints / indexes |
|---|---|---|
| `app_user` | id, email, email_normalized, password_hash NULL, status (`PENDING_ACTIVATION`/`ACTIVE`/`DISABLED`), email_verified_at, last_login_at, timezone | UNIQUE(email_normalized); password_hash NULL only while PENDING_ACTIVATION |
| `session` | id, user_id → app_user, token_hash, csrf_secret_hash, created_at, last_seen_at, expires_at, revoked_at, ip_hash, user_agent_hash | UNIQUE(token_hash); index(user_id) WHERE revoked_at IS NULL |
| `user_preference` | user_id PK → app_user, selected_org_id NULL | FK(selected_org_id, user_id) → organization_member(organization_id, user_id); UI preference only, never read by authorization; created in migration `0002` because it references organization membership |
| `auth_throttle` | scope (`ACCOUNT`/`IP`), key_hash, failure_count, window_started_at, locked_until, updated_at | PK(scope, key_hash); failed-login counters keyed by hashed email (existing or not) and hashed IP (FR-ID-001; approved G1 security-support table, IC-05) |
| `auth_token` | id, user_id → app_user, purpose (`ACTIVATION`/`PASSWORD_RESET`), token_hash, expires_at, used_at, created_by NULL | UNIQUE(token_hash); single-use (used_at set atomically) |
| `platform_admin` | user_id PK → app_user, status (`ACTIVE`/`DEACTIVATED`), granted_by NULL → app_user, granted_at, deactivated_by, deactivated_at | last-ACTIVE protection in service transaction under advisory lock; NULL granted_by only for bootstrap |
| `platform_admin_invitation` | id, email_normalized, token_hash, invited_by → app_user, expires_at, accepted_at, revoked_at | UNIQUE(token_hash); partial UNIQUE(email_normalized) WHERE pending |
| `platform_settings` | id = 1, default_max_monitors, min_interval_seconds, max_timeout_ms, max_retry_attempts, max_custom_headers, validation_max_bytes, check_now_per_monitor_seconds, check_now_per_org_hour, default_max_status_pages, default_max_channels, updated_by, version | CHECK(id = 1), single row; CHECK ranges (e.g. min_interval_seconds ≥ 60) |
| `worker_heartbeat` | worker_id PK, kind (`WORKER`/`NOTIFIER`), last_seen_at, in_flight, version_label | operational only, contains no tenant data |

### 2.2 Organizations and membership
| Table | Columns | Constraints / indexes |
|---|---|---|
| `organization` | id, slug, name, timezone, status (`ACTIVE`/`SUSPENDED`), suspended_at, suspended_reason, created_by → app_user, version | UNIQUE(slug); row locked (`FOR UPDATE`) for membership, limit and lifecycle changes |
| `organization_limit` | organization_id PK → organization, max_monitors NULL, min_interval_seconds NULL, max_status_pages NULL, max_channels NULL, updated_by, version | NULL = platform default; effective = COALESCE(override, platform_settings) |
| `organization_member` | organization_id → organization, user_id → app_user, role (`ORG_OWNER`/`ORG_ADMIN`/`ORG_MEMBER`/`VIEWER`), status (`ACTIVE`/`SUSPENDED`/`REMOVED`), invited_by, joined_at, status_changed_at, version | PK(organization_id, user_id); index(user_id) WHERE status = 'ACTIVE'; last-owner invariant in service transaction under organization row lock |
| `org_invitation` | id, organization_id, email_normalized, role, token_hash, invited_by → app_user, invited_by_plane (`ORG`/`PLATFORM`), expires_at, accepted_at, revoked_at | UNIQUE(token_hash); partial UNIQUE(organization_id, email_normalized) WHERE pending; CHECK role IN org roles |

### 2.3 Catalog
| Table | Columns | Constraints / indexes |
|---|---|---|
| `project` | id, organization_id, name, description, archived_at, version | UNIQUE(organization_id, id); UNIQUE(organization_id, lower(name)) WHERE archived_at IS NULL |
| `verified_domain` | id, organization_id, fqdn, method (`DNS_TXT`/`ADMIN_EXCEPTION`), challenge_token_hash, challenge_expires_at, status (`PENDING`/`VERIFIED`/`EXPIRED`/`REJECTED`/`REVOKED`), verified_at, expires_at, last_checked_at, exception_reason, decided_by NULL → app_user, created_by | UNIQUE(organization_id, id); UNIQUE(organization_id, fqdn); covers fqdn and its subdomains |
| `monitor` | id, organization_id, project_id, kind (`HTTP`), name, url_ciphertext, url_key_id, hostname, display_url (scheme + host + path, no query), method (`GET`/`HEAD`), interval_seconds, timeout_ms, retry_attempts, expected_status_json, validation_json NULL, header_ciphertext NULL, header_key_id NULL, header_count, latency_threshold_ms, failure_threshold, recovery_threshold, tls_warn_days, tags_json, lifecycle (`DRAFT`/`ACTIVE`/`PAUSED`/`ARCHIVED`), paused_reason (`USER`/`POLICY_BLOCKED`) NULL, attention_reason NULL, version | UNIQUE(organization_id, id); FK(organization_id, project_id) → project; CHECK interval IN (60, 120, 300); CHECK timeout_ms 3000–15000; CHECK retry_attempts 0–2; CHECK header_count 0–5; CHECK validation_json IS NULL OR method = 'GET'; CHECK kind = 'HTTP' in Phase 1 (relaxed by a Phase 2 migration) |
| `monitor_schedule` | monitor_id, organization_id, next_due_at, planned_due_at, generation, lease_owner, lease_until, current_job_id, current_trigger, manual_check_requested_at, last_manual_check_requested_at, missed_slots | PK(monitor_id); FK(organization_id, monitor_id) → monitor; index(next_due_at) |
| `monitor_health` | monitor_id, organization_id, state (`UNKNOWN`/`UP`/`DEGRADED`/`DOWN`), consecutive_failures, consecutive_successes (PASS or SLOW), consecutive_passes (PASS only, for `DEGRADED → UP`), consecutive_slow, consecutive_blocked, last_measurement_id, last_conclusive_at, last_change_at, version | PK(monitor_id); FK(organization_id, monitor_id) → monitor; row lock during evaluation |

### 2.4 Measurements
| Table | Columns | Constraints / indexes |
|---|---|---|
| `measurement` | id, organization_id, monitor_id, job_id NULL, trigger (`SCHEDULED`/`MANUAL`), source_kind (`HTTP_PROBE`; reserved `AGENT_METRIC`), schema_version, scheduled_for, observed_at, ingested_at, result (`PASS`/`SLOW`/`FAIL`/`BLOCKED`/`INCONCLUSIVE`), failure_category NULL, http_status NULL, elapsed_ms NULL, attempt_count, tls_not_after NULL, value_numeric NULL (reserved for Phase 2) | UNIQUE(organization_id, id); FK(organization_id, monitor_id) → monitor; partial UNIQUE(monitor_id, job_id) WHERE job_id IS NOT NULL; index(organization_id, monitor_id, observed_at DESC); CHECK elapsed_ms ≥ 0; contains no body, header, query string or IP |
| `hourly_monitor_rollup` | organization_id, monitor_id, window_start, conclusive_samples, available_samples, failed_samples, blocked_samples, inconclusive_samples, missed_slots, latency_p50_ms, latency_p95_ms, downtime_seconds_est | PK(organization_id, monitor_id, window_start); FK(organization_id, monitor_id) → monitor |

`probe_run` from draft v0.1 is merged into `measurement`. The job ID and trigger live on the measurement, and the lease lives on `monitor_schedule` (ADR-019).

### 2.5 Incidents and notifications
| Table | Columns | Constraints / indexes |
|---|---|---|
| `incident` | id, organization_id, monitor_id, type (`OUTAGE`/`TLS_EXPIRY`), source_kind (`HTTP_PROBE`), severity (`CRITICAL`/`WARNING`), status (`OPEN`/`ACKNOWLEDGED`/`RESOLVED`), title_sanitized, opened_measurement_id (no FK: measurements are retained 30 days, incidents 12 months), opened_at, acknowledged_at, acknowledged_by, resolved_at, resolved_by NULL, resolution (`AUTO`/`MANUAL`), assigned_user_id NULL, last_event_at, version | UNIQUE(organization_id, id); FK(organization_id, monitor_id) → monitor; **FK(organization_id, assigned_user_id) → organization_member(organization_id, user_id)**; partial UNIQUE(monitor_id, type) WHERE status <> 'RESOLVED'; CHECK status RESOLVED ⇔ resolved_at and resolution set; index(organization_id, status, opened_at DESC); index(organization_id, monitor_id, opened_at DESC) |
| `incident_event` | id, organization_id, incident_id, actor_kind (`USER`/`SYSTEM`), actor_user_id NULL → app_user, event_type, details_sanitized_json, created_at | UNIQUE(organization_id, id); FK(organization_id, incident_id) → incident; append-only (UPDATE/DELETE revoked from app role); event_type `OPENED`/`ACKNOWLEDGED`/`ASSIGNED`/`UNASSIGNED`/`COMMENTED`/`RESOLVED`; partial UNIQUE(incident_id, event_type) for OPENED/ACKNOWLEDGED/RESOLVED; index(organization_id, incident_id, created_at) |
| `notification_channel` | id, organization_id, type (`TELEGRAM`/`EMAIL`), label, config_ciphertext NULL (Telegram token + chat ID), config_key_id, enabled, created_by, created_at, updated_at, version | UNIQUE(organization_id, id); CHECK TELEGRAM ⇔ config set |
| `notification_channel_recipient` | organization_id, channel_id, user_id | PK(channel_id, user_id); FK(organization_id, channel_id) → notification_channel; **FK(organization_id, user_id) → organization_member**; EMAIL channels only |
| `notification_route` | id, organization_id, channel_id, project_id NULL, monitor_id NULL, event_types_json, enabled | FK(organization_id, channel_id) → channel; FK(organization_id, project_id) → project; FK(organization_id, monitor_id) → monitor; CHECK NOT (project_id IS NOT NULL AND monitor_id IS NOT NULL) |
| `notification_outbox` | id, organization_id, incident_id NULL, incident_event_id NULL, monitor_id NULL, channel_id, event_type, dedupe_key, state (`PENDING`/`LEASED`/`SENT`/`FAILED`/`CANCELLED`), cancel_reason, attempts (≤ 8), next_attempt_at, lease_until, lease_token, last_result_code, created_at, sent_at | FK(organization_id, channel_id) → channel; FK(organization_id, incident_id) → incident; FK(organization_id, incident_event_id) → incident_event; FK(organization_id, monitor_id) → monitor; UNIQUE(organization_id, dedupe_key); partial index(next_attempt_at) WHERE state = 'PENDING' |
| `notification_delivery` | id, organization_id, outbox_id, attempt, recipient_user_id NULL (email), result_code, provider_ref NULL, attempted_at | FK(organization_id, outbox_id) → outbox (requires UNIQUE(organization_id, id) on outbox); no message body or secrets |

The outbox stores references, not rendered payloads. The notifier renders sanitized content at dispatch from organization-scoped rows (FR-NTF-004/005).

### 2.6 Status pages and audit
| Table | Columns | Constraints / indexes |
|---|---|---|
| `status_page` | id, organization_id, public_slug, title, enabled (published; default false), created_by, created_at, updated_at, version | UNIQUE(organization_id, id); UNIQUE(public_slug) (global) |
| `status_page_monitor` | organization_id, status_page_id, monitor_id, public_display_name, sort_order | PK(status_page_id, monitor_id); FK(organization_id, status_page_id) → status_page; FK(organization_id, monitor_id) → monitor |
| `status_page_snapshot` | status_page_id PK, organization_id, generated_at, safe_payload_json | FK(organization_id, status_page_id) → status_page; payload built from an allowlist |
| `audit_event` | id, scope (`PLATFORM`/`ORGANIZATION`), organization_id NULL → organization (FK added in `0002`), actor_kind (`USER`/`SYSTEM`/`CLI`), actor_user_id NULL, actor_plane (`PLATFORM`/`ORG`/`NONE`), action, entity_kind, entity_id, safe_diff_json, request_id, at | CHECK scope = 'ORGANIZATION' ⇒ organization_id NOT NULL; index(organization_id, at DESC); index(scope, at DESC); INSERT/SELECT only for the app role; secrets and ciphertext are never written |

## 3. Relationships
```text
app_user ──< organization_member >── organization ──1 organization_limit
app_user ──1 platform_admin            organization ──< org_invitation
app_user ──< session, auth_token       organization ──< verified_domain
organization ──< project ──< monitor ──1 monitor_schedule
                                  monitor ──1 monitor_health
                                  monitor ──< measurement
                                  monitor ──< hourly_monitor_rollup
                                  monitor ──< incident ──< incident_event
organization_member ──< incident (assigned_user_id, composite)
organization ──< notification_channel ──< notification_route (>── project | monitor)
notification_channel ──< notification_channel_recipient >── organization_member
incident / incident_event ──< notification_outbox ──< notification_delivery
organization ──< status_page ──< status_page_monitor >── monitor
status_page ──1 status_page_snapshot
audit_event >── organization (nullable)
```

## 4. Organization isolation review
| Risk | Control |
|---|---|
| API reads another organization's row by ID | All repository calls require `organization_id` from the validated path context; integration tests probe every route with foreign IDs and expect 404 |
| Child linked to a parent in another organization | Composite FKs on every tenant reference (monitor→project, schedule/health/measurement/rollup/incident→monitor, event→incident, route/outbox/recipient→channel, route→project/monitor, status_page_monitor→page and monitor, outbox→incident/event, delivery→outbox) |
| Incident assigned to a non-member | Composite FK to `organization_member`; service requires ACTIVE status and unassigns on removal |
| Email alert to a non-member | Recipients are composite FK rows on `organization_member`, re-checked ACTIVE at dispatch |
| Worker writes with the wrong organization | Worker takes `organization_id` from the claimed `monitor_schedule` row, never from job input. Composite FKs reject mismatches |
| Notification job crosses organizations | Outbox → channel composite FK. The notifier re-validates channel organization and state |
| Ciphertext copied between organizations | AES-GCM associated data includes `organization_id`, table, row and field |
| Export leaks data | Streamed per request, organization-scoped queries, aggregate columns only |
| Public page leaks private data | Reads only `status_page_snapshot` built from an allowlist |
| SYSTEM_ADMIN reads organization secrets | Platform queries use metadata-only views (§5); the `platform` module cannot import the secrets module |
| Suspended organization still active | Claim query joins `organization.status = 'ACTIVE'`. Notifier cancels; API returns 403; public page returns 404 |
| Last owner removed concurrently | Organization row `FOR UPDATE` before counting active owners |
| Limit overshoot under concurrency | Organization row `FOR UPDATE` before counting non-archived monitors |

Row-Level Security is not used in Phase 1. Isolation relies on the scoped repository layer, composite FKs and the isolation test suite. RLS is tracked as OD-09.

## 5. Platform (SYSTEM_ADMIN) read model
Views `v_platform_org_summary` (organization ID, slug, name, status, created_at, owner emails, counts of members, projects, monitors by lifecycle, status pages and channels, open incidents by severity, effective limits), `v_platform_usage_daily` (organization ID, day, measurements by result, incidents opened, notifications sent/failed) and `v_platform_queue_health` (claim backlog and lag, checks in flight and volume, outbox backlog, lag and failures; IC-26), all built from aggregates. These views exclude ciphertext, `hostname`, `display_url`, header/validation data, channel configuration, incident titles and events. Platform endpoints may read only these views, `organization`, `organization_limit`, `verified_domain` (fqdn, method, status, expiry), `platform_*` tables, `worker_heartbeat` and `audit_event`.

## 6. Atomic flows
**Complete probe:** one transaction: verify the job and generation → insert measurement (duplicate job = no-op returning the prior result) → if scheduled and conclusive, lock `monitor_health`, apply thresholds, create/resolve incident plus event, insert outbox rows → update schedule. Serialization/deadlock retries are bounded. Alerts are never sent before commit.

**Membership change:** lock organization → validate actor's assignable roles → check active owner count after change ≥ 1 → update → unassign incidents and remove channel recipients if the membership becomes inactive → audit.

**Suspension:** lock organization → status SUSPENDED → increment generation on all its schedules → cancel PENDING outbox rows → audit (scope PLATFORM, with organization_id). **Activation:** status ACTIVE → reset health to UNKNOWN → increment generation → audit.

**Status publication:** a periodic or event-triggered task builds the snapshot in one transaction from allowlisted fields.

## 7. Migration plan (logical; not created now)
- `0001_identity_platform`: app_user, session, auth_token, auth_throttle, platform_admin, platform_admin_invitation, platform_settings, audit_event (organization_id without FK), worker_heartbeat.
- `0002_organizations`: organization, organization_limit, organization_member, org_invitation, user_preference, project; adds the `audit_event.organization_id → organization` FK.
- `0003_catalog`: verified_domain, monitor, monitor_schedule, monitor_health.
- `0004_measurements`: measurement, hourly_monitor_rollup, indexes.
- `0005_incidents` (G4): incident, incident_event, `monitor_health.consecutive_passes`.
- `0006_notifications` (G5): notification_channel, notification_channel_recipient, notification_route, notification_outbox, notification_delivery.
- `0007_status_pages` (G5): status_page, status_page_monitor, status_page_snapshot.
- `0008_platform_views` (G6): `v_platform_org_summary`, `v_platform_usage_daily`, `v_platform_queue_health`; retention indexes and DELETE grants on `measurement` and `hourly_monitor_rollup` (IC-24, IC-27).

`platform_settings` default values are inserted by migration `0001` as configuration, not as a seed. **No user, organization or credential is ever created by a migration.** Migrations require explicit approval before applying to any non-disposable database. Demo fixtures may only target a named `_test` or `_demo` database after separate confirmation.

## 8. Indexing and query performance
- `monitor_schedule(next_due_at)` with the claim join; batch-limited.
- `measurement(organization_id, monitor_id, observed_at DESC)` for 24h/7d/30d.
- `incident(organization_id, status, opened_at DESC)`.
- `notification_outbox(next_attempt_at) WHERE state = 'PENDING'`.
- `organization_member(user_id) WHERE status = 'ACTIVE'` for organization switching.
- `measurement(observed_at)` and `hourly_monitor_rollup(window_start)` for retention batches.
- Monthly measurement partitioning only when needed. Retention deletes in batches.
- Uptime = available_samples / conclusive_samples, with coverage = conclusive / expected slots reported alongside. Paused time, missed, BLOCKED and INCONCLUSIVE samples are excluded from the denominator and shown as coverage gaps.

## 9. Phase 2 evolution
Future tables, all organization-owned with composite FKs: `telemetry_source` (organization_id, project_id NULL, credential hash, status), `metric_definition`, `metric_sample` (or a dedicated time-series store), `monitor_metric_rule` (organization_id, monitor_id, metric, operator, threshold, window). Phase 2 relaxes `monitor.kind` to add `METRIC_THRESHOLD` and makes `url_ciphertext`/`hostname` nullable for non-HTTP kinds through a CHECK by kind. Evaluator results are written to `measurement` with `source_kind = AGENT_METRIC`, so health, incident, notification, report and permission tables are unchanged. Raw high-cardinality samples never go into `measurement`.
