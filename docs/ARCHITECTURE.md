# Architecture overview

A summary of the implemented system. The normative design is
[baseline-v1.0/02_TECHNICAL_ARCHITECTURE.md](baseline-v1.0/02_TECHNICAL_ARCHITECTURE.md) and
[03_DATABASE_DESIGN.md](baseline-v1.0/03_DATABASE_DESIGN.md); implementation choices are recorded
as IC-01…IC-31 in [ARCHITECTURE_DECISIONS.md](baseline-v1.0/ARCHITECTURE_DECISIONS.md).

## Processes

| Process | Entry point | Responsibility |
|---|---|---|
| `api` | `uvicorn sentinelops.api.app:create_app` | REST API, sessions/CSRF, SSE, public status endpoint |
| `worker` | `python -m sentinelops.worker` | Claims due monitors, runs SSRF-safe probes, records results, health/incident transitions, rollups, retention, staleness, status snapshots |
| `notifier` | `python -m sentinelops.notifier` | Leases outbox rows, re-validates, delivers via Telegram / SMTP relay, records delivery history |
| `migrate` | `alembic upgrade head` | Manual only; never automatic |

## Modules (`apps/api/src/sentinelops`)

```mermaid
flowchart TB
    subgraph planes[Authorization planes]
      platform[platform: SYSTEM_ADMIN console]
      tenancy[tenancy: orgs, memberships, OrgPermission]
    end
    identity[identity: users, sessions, CSRF, MFA, throttling]
    authz[authz: ORG_PERMISSIONS table]
    catalog[catalog: projects, domains, monitors]
    probes[probe_policy + probes.http: SSRF-safe engine]
    scheduler[scheduler: leases, runner, worker loop]
    incidents[incidents: state machine, timeline]
    notifications[notifications: channels, outbox, dispatcher]
    measurements[measurements: results, rollups, reports]
    status[status_pages: snapshots, public endpoint]
    realtime[realtime: SSE over LISTEN/NOTIFY]
    secrets[secrets: AES-GCM SecretBox]
    platform --> identity
    tenancy --> authz
    catalog --> secrets
    scheduler --> probes
    scheduler --> incidents
    incidents --> notifications
    notifications --> secrets
    platform -. forbidden .-> secrets
```

Import boundaries are enforced by import-linter: the platform plane can never import
`sentinelops.secrets` (ADR-005), and domain modules never import process entrypoints.

## Data model (ownership chain)

```mermaid
erDiagram
    organization ||--o{ organization_member : has
    organization ||--o{ project : owns
    organization ||--o{ verified_domain : proves
    project ||--o{ monitor : groups
    monitor ||--|| monitor_schedule : "lease state"
    monitor ||--|| monitor_health : "state machine"
    monitor ||--o{ measurement : "raw, 30 days"
    monitor ||--o{ hourly_monitor_rollup : "12 months"
    monitor ||--o{ incident : raises
    incident ||--o{ incident_event : "append-only timeline"
    incident ||--o{ notification_outbox : notifies
    notification_channel ||--o{ notification_outbox : delivers
    notification_outbox ||--o{ notification_delivery : attempts
    organization ||--o{ status_page : publishes
    status_page ||--|| status_page_snapshot : "allowlisted payload"
```

Every tenant table carries `organization_id`; parents have `UNIQUE(organization_id, id)` and
children reference `(organization_id, parent_id)`, so a row can never point into another
organization. The app connects as a least-privilege role (no DDL; append-only tables have no
UPDATE/DELETE grant).

## Check lifecycle

1. **Claim:** `FOR UPDATE SKIP LOCKED` over due schedules of ACTIVE monitors in ACTIVE
   organizations; each claim gets a lease and job ID; domain coverage is re-checked.
2. **Probe** (no transaction open): parse URL → resolve → validate every A/AAAA answer → connect to
   the validated IP with original Host/SNI → GET/HEAD, no redirects → classify PASS / SLOW / FAIL /
   BLOCKED / INCONCLUSIVE.
3. **Complete** (one transaction): verify job ID and generation → insert the measurement
   idempotently → for scheduled conclusive results apply the health state machine, open/resolve
   incidents, append timeline events, enqueue outbox rows, `pg_notify` → advance the schedule.
4. **Notify:** the notifier leases outbox rows, re-validates (org active, channel enabled,
   recipients still members, notice not superseded), sends, records results, retries with backoff.

## Realtime and reporting

- `pg_notify` inside the committing transaction → one LISTEN connection per API process →
  per-organization SSE subscribers (bounded queues, `resync` on overflow or reconnect).
- Reports use one source per hour: the rollup if the hour is fully inside the window, otherwise raw
  measurements. Uptime = available / conclusive; coverage = conclusive / expected slots.

## Platform plane

SYSTEM_ADMIN endpoints read only organization metadata and the aggregate views
`v_platform_org_summary`, `v_platform_usage_daily` and `v_platform_queue_health`. A SYSTEM_ADMIN
has no implicit membership: organization routes return `404` unless they are invited.
