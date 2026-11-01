# SentinelOps — Technical Architecture · Baseline v1.0 · 31 Oct 2026

Requirements: `01_SRS.md`. Authorization: `PERMISSION_MATRIX.md`. Decisions: `ARCHITECTURE_DECISIONS.md`. Data model: `03_DATABASE_DESIGN.md`.

## 1. Architecture goals
Python-first, multi-tenant, language-agnostic monitoring with predictable scheduling, secure egress, strict organization isolation and a separate platform administration plane. Phase 1 is agentless public HTTP(S) only. Phase 2 adds adapter-based agent metrics without changing ownership. The system is a **modular monolith**: one Python codebase, deployed as an API process, a worker process and a notifier process, with PostgreSQL as the only stateful dependency. No Celery, Redis, message broker or microservices (ADR-001).

## 2. Stack and repository
- **Backend:** Python (current stable release pinned at G0 via lock file), FastAPI, Pydantic v2, SQLAlchemy 2 (async, asyncpg), Alembic, HTTPX + asyncio for probes, `cryptography` (AES-GCM) for secrets, Argon2id for passwords. Pytest/pytest-asyncio, Ruff, mypy or Pyright (chosen at G0).
- **Frontend:** React + TypeScript (Vite), TanStack Query, SSE client. Playwright for E2E. Styling library chosen at G0.
- **Database:** PostgreSQL 16+. Plain indexed tables in MVP; measurement partitioning only when load requires it.
- **Deployment:** Docker Compose services `postgres`, `migrate` (manual profile, never automatic), `api`, `worker`, `notifier`, `web`, and `mailcatcher` (dev profile only). Optional reverse proxy for TLS. No paid services.
- **Repository:** `apps/api` (Python package with `api`, `worker`, `notifier`, `cli` entrypoints), `apps/web`, `infra/`, `docs/`, `tests/`.

## 3. Logical flow
```text
                         ┌──────────── platform plane (/api/admin/*) ─ SYSTEM_ADMIN only
Browser ── HTTPS ──> FastAPI ─┤
                         └──────────── org plane (/api/orgs/{org_id}/*) ─ ACTIVE membership only
                                   │                 ▲ SSE (per org, per membership)
                                   ▼                 │
                               PostgreSQL ── LISTEN/NOTIFY ──┘
                                ▲     ▲
   worker: claim due monitors ──┘     └── notifier: lease outbox rows ──> Telegram API / platform SMTP
     │  (SKIP LOCKED leases)
     └── probe_policy + pinned-IP HTTPX transport ──> PUBLIC endpoint (egress firewall)
     └── evaluator: measurement → health → incident → outbox (one transaction)
     └── periodic tasks (advisory-locked): rollups, retention, staleness, status snapshots,
         domain re-verification

[Phase 2] Grafana Alloy ──> authenticated receiver ──> metric samples ──> evaluator (same incident path)
```

## 4. Modular boundaries
- `identity`: accounts, sessions, CSRF, invitations, activation/reset tokens.
- `platform`: SYSTEM_ADMIN plane: bootstrap CLI, platform admins, organization lifecycle, limits, settings, platform dashboard, domain exceptions. Has **no import dependency** on modules that decrypt organization secrets (enforced by an import-linter rule).
- `tenancy`: organizations, memberships, role rules, last-owner invariant, organization context resolution.
- `authz`: single policy function `authorize(principal, org_id, action)`, generated from `PERMISSION_MATRIX.md` as a static table.
- `catalog`: projects, monitors, domain verification, limits enforcement.
- `secrets`: encryption/decryption with organization-bound associated data. Callable only from `catalog` (write), `probes` and `notifications` (read).
- `probe_policy`: URL parsing, DNS resolution, IP classification, destination decision.
- `probes/http`: pinned-IP HTTPX transport and HTTP adapter, returning a normalized `CheckOutcome`.
- `scheduler`: claim/lease/complete logic used by the worker.
- `measurements`: append-only results, rollups, retention.
- `incidents`: pure state machine plus transactional orchestration.
- `notifications`: outbox, channels, retries, deduplication.
- `status_pages`: snapshot generation and public read.
- `realtime`: organization-scoped SSE.
- `audit`: append-only audit writer.

## 5. Scheduling and probe execution
**Claim (worker loop):**
```sql
SELECT s.* FROM monitor_schedule s
JOIN monitor m ON (m.organization_id, m.id) = (s.organization_id, s.monitor_id)
JOIN organization o ON o.id = s.organization_id
WHERE o.status = 'ACTIVE' AND m.lifecycle = 'ACTIVE'
  AND (s.next_due_at <= now() OR s.manual_check_requested_at IS NOT NULL)
  AND (s.lease_until IS NULL OR s.lease_until < now())
ORDER BY s.next_due_at
LIMIT :batch FOR UPDATE OF s SKIP LOCKED;
```
Domain coverage is checked for claimed rows. Uncovered monitors move to DRAFT with an attention reason. The claim sets `lease_owner`, `lease_until = now() + timeout × (retries + 1) + retry_delays + 10 s` and a new `current_job_id`, then commits. DB time is the reference clock.

**Concurrency:** per worker process, a global semaphore (default 50), a per-organization semaphore (default 10) and a per-destination-host semaphore (default 2). The claim batch is sized to free capacity. With N workers the effective caps are N times these values; there is no global cross-worker enforcement. The MVP-supported topology is a single worker process (IC-09). Lease claims stay correct with more workers, but the caps then apply per process. Values come from environment configuration, not the DB.

**Probe:** runs outside any DB transaction. For each attempt: resolve → validate every answer → connect to a validated IP → send GET/HEAD with fixed User-Agent and decrypted custom headers → read at most the validation byte cap → evaluate → discard the body. Timeouts: connect, TLS handshake, read and total deadline, all bounded by `timeout_ms`. Retries follow SRS FR-MON-011.

**Complete (one transaction):** verify `job_id` equals `current_job_id` and generation is unchanged, otherwise discard. Insert `measurement` (unique `(monitor_id, job_id)` makes duplicates no-ops). For scheduled conclusive results, lock `monitor_health`, apply the state machine, create or resolve incidents and events, and insert outbox rows. Clear the lease. Advance `next_due_at = planned_due + interval`, skipping to the next future slot if more than one interval behind and incrementing `missed_slots`. For MANUAL jobs, clear `manual_check_requested_at` only.

**Generation:** `monitor_schedule.generation` is incremented on monitor edit, pause, resume, archive and organization activation. Late completions from older generations are discarded without side effects.

**Staleness:** a periodic task sets health UNKNOWN when there is no conclusive scheduled result for 3 intervals. It does not resolve incidents.

## 6. State machines
**Health** (inputs: scheduled PASS/SLOW/FAIL only):
- `UNKNOWN → UP` on first PASS or SLOW (then DEGRADED rules apply). `UNKNOWN → DOWN` after `failure_threshold` consecutive FAIL.
- `UP → DEGRADED` after `failure_threshold` consecutive SLOW. `DEGRADED → UP` after `recovery_threshold` consecutive PASS.
- `UP/DEGRADED → DOWN` after `failure_threshold` consecutive FAIL. `DOWN → UP` after `recovery_threshold` consecutive PASS/SLOW.
- BLOCKED and INCONCLUSIVE leave counters untouched. 3 consecutive BLOCKED → lifecycle PAUSED (reason POLICY_BLOCKED) plus a notification.
- Lifecycle PAUSED and organization suspension stop evaluation. Resume or activation resets health to UNKNOWN and counters to 0.

**Incident:** OUTAGE opens on entering DOWN and resolves on `DOWN → UP`. TLS_EXPIRY opens when certificate days remaining < threshold and resolves when it is ≥ threshold. Status OPEN → ACKNOWLEDGED → RESOLVED. Manual resolve of OUTAGE is rejected while health is DOWN. A partial unique index enforces at most one active incident per (monitor, type). `incident_event` is append-only and records actor kind USER or SYSTEM.

## 7. SSRF and probe isolation (release-critical)
**Never use naive `httpx.get(user_url)`.** Requirements:
1. Parse with a strict URL parser. Reject non-http(s) schemes, userinfo, fragments, ports other than 80/443, IP-literal hosts (including decimal, octal, hex and IPv6 literal forms) and hostnames that fail IDNA normalization.
2. Resolve all A and AAAA records with a resolver whose timeout fits the check deadline. If **any** answer is forbidden (SRS FR-MON-004 list, evaluated with `ipaddress`, including IPv4-mapped/compatible, NAT64 `64:ff9b::/96`, 6to4 and Teredo embeddings), the result is BLOCKED.
3. Connect to one validated IP through a custom HTTPX transport/network backend that **performs no second DNS lookup**, while preserving the original Host header, TLS SNI and certificate hostname verification.
4. `trust_env=False` (no proxies, no netrc), `follow_redirects=False`, HTTP/1.1 only in MVP, response size and header count caps, fixed User-Agent identifying SentinelOps.
5. Re-run steps 1–4 on every attempt and every check. No caching of decisions across checks.
6. Defense in depth: probe egress leaves through a dedicated network path whose firewall denies RFC 1918, loopback, link-local, metadata and the Compose internal networks, so a policy bug cannot reach `postgres`, `api` or host services through the probe client. The worker's DB connection uses a separate internal network.
7. The policy is code, not data. No organization role or SYSTEM_ADMIN setting can extend the allowed destinations. The development fixture policy is enabled only by `PROBE_POLICY=dev-fixtures`, which the process refuses outside `ENV=development|test`. Tests mock the transport rather than opening localhost egress.
8. Negative tests: DNS rebinding between validation and connect, mixed public/private answers, CNAME to private IP, encoded IP forms, IPv6 and mapped forms, 30x to private targets (not followed), proxy environment variables present, oversized responses, slowloris-style trickle responses.

If a pinned-IP transport with intact SNI/certificate verification cannot be demonstrated in G3, **stop and report** rather than ship a weaker connector.

## 8. Authentication, tenancy, platform plane and privacy
**Sessions:** opaque random token in an HttpOnly, Secure (in TLS deployments), SameSite=Lax cookie. Only the token hash is stored. CSRF token is required on mutations. Sessions rotate on login, password change and platform-role change. Login throttling applies per account and per IP.

**Request authorization pipeline:**
1. Authenticate the session → `principal(user_id)`. Reject if the user is not ACTIVE.
2. Platform routes `/api/admin/*`: require an ACTIVE `platform_admin` row. Organization membership is irrelevant.
3. Organization routes `/api/orgs/{org_id}/*`: load the ACTIVE `organization_member` row for `(org_id, user_id)`. If there is none → 404. If the organization is SUSPENDED → 403 `ORG_SUSPENDED`. Then `authz.authorize(role, action)` → 403 if denied. `platform_admin` is never consulted.
4. Every repository function for tenant data takes `organization_id` as a required argument and includes it in the `WHERE` clause and in inserts. Entity IDs from the client are never trusted to imply an organization. A lint/test rule forbids unscoped queries on tenant tables.

**Organization switching:** `GET /api/me/organizations` returns ACTIVE memberships with organization state. `PUT /api/me/preferences {selected_org_id}` stores a UI preference only after verifying membership. The frontend routes `/o/{org_slug}/...` resolve to `org_id` from the membership list. The TanStack Query cache is keyed by `org_id` and cleared on switch. The SSE stream is closed and reopened for the new organization.

**Last-owner and role rules:** membership mutations run in one transaction that first runs `SELECT … FROM organization WHERE id = :org FOR UPDATE`, then checks the active owner count and the actor's assignable roles (`PERMISSION_MATRIX.md` §4). The same lock serializes monitor-limit checks.

**SYSTEM_ADMIN bootstrap:** CLI `bootstrap-system-admin --email` runs inside the `api` container. In one transaction it takes an advisory lock, verifies there is no ACTIVE `platform_admin`, creates `app_user` (status PENDING_ACTIVATION, no password) and a `platform_admin` row, stores the SHA-256 hash of a 256-bit random activation token (30-minute expiry) and writes an audit event. It prints the activation URL once to stdout. `--recover` issues a new activation token for an existing SYSTEM_ADMIN (resetting their password and sessions) and is audited. No HTTP endpoint can create the first admin.

**SYSTEM_ADMIN isolation:** platform APIs read only metadata columns and aggregate views (`03_DATABASE_DESIGN.md` §5). The `platform` module cannot import `secrets`. Impersonation does not exist. Platform actions affecting an organization write audit events visible to its owners.

**Secrets:** AES-256-GCM, key ring from `SECRET_KEYS` (key ID → key, from environment or secret file, never committed). Associated data = `organization_id | table | row_id | field`, so a ciphertext copied to another organization or row fails to decrypt. Encrypted fields: monitor URL, custom headers, Telegram bot token and chat ID. Custom headers and Telegram credentials are **write-only secrets**: no API returns them after save. The monitor URL is encrypted at rest because it may carry query tokens, but it is configuration: its decrypted form is returned only to `MON.update` holders in the edit form, and everywhere else `display_url` is used. Key rotation re-encrypts in batches. Residual risk: holders of keys plus DB access can decrypt (NFR-011).

**Public data boundary:** public status endpoints read only `status_page_snapshot.safe_payload_json`, never live private tables. Payload fields come from an explicit allowlist.

## 9. API contract sketch
**Auth and self:** `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, `POST /api/auth/activate`, `POST /api/auth/password-reset/request`, `POST /api/auth/password-reset/confirm`, `POST /api/invitations/{token}/accept`, `GET /api/me/organizations`, `PUT /api/me/preferences`.

**Platform plane (SYSTEM_ADMIN):** `GET /api/admin/dashboard`, `GET/POST /api/admin/organizations`, `GET/PATCH /api/admin/organizations/{id}`, `POST /api/admin/organizations/{id}/suspend`, `POST /api/admin/organizations/{id}/activate`, `PUT /api/admin/organizations/{id}/limits`, `POST /api/admin/organizations/{id}/owner-invitations`, `GET/POST /api/admin/platform-admins`, `POST /api/admin/platform-admins/{user_id}/deactivate`, `GET/PUT /api/admin/settings`, `GET /api/admin/domain-exceptions`, `POST /api/admin/domain-exceptions/{id}/approve|reject`, `GET /api/admin/audit`.

**Organization plane:** `GET/PATCH /api/orgs/{org}`, `GET /api/orgs/{org}/members`, `POST /api/orgs/{org}/invitations`, `DELETE /api/orgs/{org}/invitations/{id}`, `PATCH /api/orgs/{org}/members/{user_id}` (role/status), `DELETE /api/orgs/{org}/members/{user_id}`, `POST /api/orgs/{org}/leave`, `GET/POST /api/orgs/{org}/projects`, `PATCH /api/orgs/{org}/projects/{id}`, `GET/POST /api/orgs/{org}/domains`, `POST /api/orgs/{org}/domains/{id}/verify`, `POST /api/orgs/{org}/domains/exception-requests`, `GET/POST /api/orgs/{org}/monitors`, `GET/PATCH /api/orgs/{org}/monitors/{id}`, `PUT /api/orgs/{org}/monitors/{id}/headers`, `POST /api/orgs/{org}/monitors/{id}/pause|resume|archive`, `POST /api/orgs/{org}/monitors/{id}/check-now`, `GET /api/orgs/{org}/monitors/{id}/measurements`, `GET /api/orgs/{org}/incidents`, `GET /api/orgs/{org}/incidents/{id}`, `POST /api/orgs/{org}/incidents/{id}/ack|assign|comment|resolve`, `GET/POST /api/orgs/{org}/notification-channels`, `PATCH /api/orgs/{org}/notification-channels/{id}`, `POST /api/orgs/{org}/notification-channels/{id}/test`, `GET/POST /api/orgs/{org}/notification-routes`, `PATCH/DELETE /api/orgs/{org}/notification-routes/{id}`, `GET /api/orgs/{org}/notification-deliveries`, `GET /api/orgs/{org}/dashboard`, `GET /api/orgs/{org}/reports`, `GET /api/orgs/{org}/reports/export.csv`, `GET/POST /api/orgs/{org}/status-pages`, `GET/PATCH /api/orgs/{org}/status-pages/{id}`, `POST /api/orgs/{org}/status-pages/{id}/publish|unpublish`, `GET /api/orgs/{org}/status-pages/{id}/preview`, `GET /api/orgs/{org}/audit`, `GET /api/orgs/{org}/events` (SSE).

**Public:** `GET /api/status/{public_slug}`.

All mutations use optimistic `version` checks or idempotency keys where effects could repeat. Each route declares its `PERMISSION_MATRIX.md` action ID. A test asserts that every route has exactly one declared action.

## 10. Notification semantics
Outbox rows are inserted in the same transaction as the incident transition, with a deterministic `dedupe_key` (`incident_id:event_type:channel_id`). The notifier leases due rows with `SKIP LOCKED` and re-validates them (organization ACTIVE, channel enabled and same organization, recipients still ACTIVE members). It renders the message at dispatch from sanitized organization-scoped fields, sends with a timeout (Telegram: fixed `api.telegram.org` host; email: platform SMTP relay) and records a `notification_delivery` row. It retries with exponential backoff (max 8 attempts), then marks the row FAILED. Providers may deliver twice on uncertain acknowledgments, so messages carry an incident reference to make duplicates recognizable. The notifier is independent of probing.

## 11. Phase 2 Grafana Alloy boundary (design only; not implemented)
Grafana Alloy is a collector, not a replacement for the probe worker. Phase 2 will add:
- `telemetry_source` (agent identity) owned by **organization** and optionally **project**, with credentials bound to that organization. The organization is derived from the credential, never from labels or payload.
- A dedicated receiver (OTLP/HTTP or Prometheus remote-write), possibly a separate process, with TLS (mTLS where feasible), token rotation, payload/cardinality/rate limits and label allowlists.
- Metric samples stored in their own table or store, not in `measurement`.
- New `monitor.kind = METRIC_THRESHOLD` monitors that reference a telemetry source and metric. Their evaluator emits normalized results into `measurement` (`source_kind = AGENT_METRIC`) and uses the same health state machine, incident model, outbox and permission matrix.

The ownership chain organization → project → monitor → measurement → incident, the composite FK pattern, the permission matrix and the SYSTEM_ADMIN metadata-only boundary therefore stay unchanged. No receiver, endpoint or agent credential exists in Phase 1.

## 12. Operations and quality
- API `/healthz` and `/readyz`. Worker and notifier heartbeats in `worker_heartbeat`. Claim lag, backlog and outbox lag feed the platform dashboard.
- Manual migration job. DB backup and restore drill. Log scrubbing (URLs reduced to host, headers dropped). Secret key management.
- Test matrix: unit (state machine, SSRF classifier, authz table); Postgres integration (isolation, composite FK rejections, last-owner and limit races, lease races); fake transport and fake clock for deterministic scheduling; Playwright for main journeys including admin console and org switching; CI dependency vulnerability scan.
- No external network in CI. No automatic migration to non-disposable DBs. Seeds only for named `_test`/`_demo` DBs after explicit approval.
- **Release blockers:** SSRF connect-time guarantee missing; any tenant isolation failure; SYSTEM_ADMIN able to read organization secrets; default credentials present; notification secret exposure; inconsistent incident dedupe; no backup/restore path.

## 13. Architectural decisions
See `ARCHITECTURE_DECISIONS.md`. The draft ADR-001…ADR-010 list from v0.1 is superseded by that file. Their mapping is recorded there.

## 14. References
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- FastAPI background task guidance: https://fastapi.tiangolo.com/tutorial/background-tasks/
- SQLAlchemy asyncio: https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html
- HTTPX transports: https://www.python-httpx.org/advanced/transports/
- Grafana Alloy docs: https://grafana.com/docs/alloy/latest/
