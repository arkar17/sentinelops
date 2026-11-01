# SentinelOps — Architecture Decision Records · Baseline v1.0 · 31 Oct 2026

**Status values**
- **Accepted (PO brief):** stated in the Product Owner decision brief of 31 Oct 2026.
- **Accepted (baseline default):** chosen during baseline consolidation where the brief is silent. It is binding for implementation. All matching open decisions in §3 were confirmed by the PO on 31 Oct 2026 (G0 approval), so these defaults are no longer provisional.
- **Superseded:** replaced by a later ADR.

Changes to an accepted ADR require a new ADR that supersedes it and a baseline version bump (`README_DOCUMENTS.md` §4).

## 1. Decision index
| ADR | Title | Status | Open decision |
|---|---|---|---|
| ADR-001 | Modular monolith with PostgreSQL-backed jobs | Accepted (PO brief) | — |
| ADR-002 | Technology stack | Accepted (PO brief) | — |
| ADR-003 | Shared-schema multi-tenancy with composite FKs | Accepted (PO brief) | OD-09 |
| ADR-004 | Global users, per-org memberships, path-based org context | Accepted (PO brief) | — |
| ADR-005 | Separate platform plane; SYSTEM_ADMIN is metadata-only | Accepted (PO brief) | OD-12, OD-13 |
| ADR-006 | SYSTEM_ADMIN bootstrap via one-time CLI | Accepted (PO brief: mechanism chosen here) | OD-01 |
| ADR-007 | Organization roles, assignment rules, last-owner invariant | Accepted (PO brief) | OD-04 |
| ADR-008 | Organizations created by SYSTEM_ADMIN; no self-signup | Accepted (baseline default) | OD-02 |
| ADR-009 | Agentless Phase 1; Alloy via adapters in Phase 2 | Accepted (PO brief) | — |
| ADR-010 | SSRF policy in code; pinned IP; no redirect following | Accepted (PO brief) | OD-06 |
| ADR-011 | Domain ownership verification before activation | Accepted (baseline default) | OD-05 |
| ADR-012 | Scheduling, concurrency, retries and result semantics | Accepted (PO brief) | — |
| ADR-013 | Incident transition and outbox in one transaction | Accepted (baseline default) | — |
| ADR-014 | Email through platform relay; Telegram fixed host | Accepted (baseline default) | OD-08 |
| ADR-015 | Application-level secret encryption bound to organization | Accepted (baseline default) | — |
| ADR-016 | Opt-in, snapshot-based public status pages | Accepted (baseline default) | — |
| ADR-017 | Default monitoring parameters | Accepted (baseline default) | OD-15 |
| ADR-018 | Server-side session cookies, not JWT | Accepted (baseline default) | — |
| ADR-019 | Unified measurement model | Accepted (baseline default) | — |
| ADR-020 | Organization suspension semantics | Accepted (baseline default) | OD-03 |
| ADR-021 | Custom request headers in Phase 1 | Accepted (baseline default) | OD-07 |

## 2. Records
### ADR-001 Modular monolith with PostgreSQL-backed jobs
**Context:** the brief asks for a simple, reliable architecture without premature microservices. **Decision:** one Python codebase deployed as `api`, `worker` and `notifier` processes. PostgreSQL is the only stateful dependency. Job claiming uses `FOR UPDATE SKIP LOCKED` leases, periodic tasks use advisory locks, and realtime fan-out uses LISTEN/NOTIFY. No Celery, Redis or broker. **Consequences:** fewer moving parts; throughput is bounded by PostgreSQL, which is adequate for the NFR-003 target. A queue can be introduced later behind the `scheduler` module interface.

### ADR-002 Technology stack
Python + FastAPI, PostgreSQL 16+, SQLAlchemy 2 (async), Alembic (manual application), HTTPX + asyncio for probes, React + TypeScript (Vite), Pytest + Playwright, Docker Compose. Secondary libraries (type checker, styling) are chosen at G0 with minimal dependencies.

### ADR-003 Shared-schema multi-tenancy with composite FKs
**Decision:** one database and schema. `organization_id` on every tenant row, `UNIQUE(organization_id, id)` on tenant parents, composite FKs on tenant references, and a mandatory organization-scoped repository layer. **Alternatives:** schema-per-tenant (operational cost); RLS (good defense in depth but adds session-variable handling with pooled async connections, so deferred to OD-09). **Consequences:** cross-org links are impossible at the DB level, and query-level isolation is enforced by code plus the isolation test harness.

### ADR-004 Global users, per-org memberships, path-based org context
**Decision:** one global `app_user`, many `organization_member` rows, each with its own role and status. The organization ID in the API path is the only authorization context and is re-validated on every request. The draft's `session.selected_org_id` is replaced by `user_preference.selected_org_id`, a UI preference never consulted for authorization. **Rationale:** stateless per-request validation prevents stale-context bugs and makes switching safe across tabs. **Consequences:** non-membership returns 404. The client must clear caches and SSE on switch.

### ADR-005 Separate platform plane; SYSTEM_ADMIN is metadata-only
**Decision:** SYSTEM_ADMIN is held in `platform_admin`, not as an organization role. Platform routes (`/api/admin/*`) and organization routes (`/api/orgs/{org}/*`) have disjoint authorization. SYSTEM_ADMIN reads only metadata views. It cannot decrypt secrets, cannot impersonate, and has no break-glass access in Phase 1. To help inside an organization, it must be invited by that organization. The `platform` module may not import `secrets`. Platform actions affecting an organization are visible in that organization's audit log. **Residual risk:** infrastructure operators with DB and key access can still decrypt; this is documented in NFR-011.

### ADR-006 SYSTEM_ADMIN bootstrap via one-time CLI
**Decision:** `bootstrap-system-admin --email` runs inside the deployment. It refuses if an ACTIVE SYSTEM_ADMIN exists, creates a passwordless account, prints a single-use 30-minute activation link (token stored hashed) and is audited. `--recover` handles total lockout and requires shell access. **Rejected:** default admin/password, password environment variables (leak into process listings and compose files), first-visitor-becomes-admin web setup (race and hijack risk), seed migrations. **Consequences:** host shell access is the root of trust, which matches who operates the deployment.

### ADR-007 Organization roles, assignment rules, last-owner invariant
**Decision:** ORG_OWNER, ORG_ADMIN, ORG_MEMBER, VIEWER, per `PERMISSION_MATRIX.md`. ORG_ADMIN may manage only ORG_MEMBER and VIEWER memberships. Nobody changes their own role, except an owner stepping down while another active owner exists. The last-owner invariant is enforced under the organization row lock. The draft's "Responder" maps to ORG_MEMBER, and the draft's "Platform Operator" to SYSTEM_ADMIN.

### ADR-008 Organizations created by SYSTEM_ADMIN; no self-signup
**Decision:** in Phase 1 only SYSTEM_ADMIN creates organizations and invites the first owner. Accounts exist only through invitation or bootstrap. **Rationale:** matches the draft's invite-based accounts, limits abuse of the probe engine, and keeps onboarding auditable. **Revisit:** OD-02.

### ADR-009 Agentless Phase 1; Alloy via adapters in Phase 2
**Decision:** Phase 1 performs only outbound HTTP(S) checks. Phase 2 adds Grafana Alloy through a dedicated authenticated receiver, `telemetry_source` owned by organization/project, metric samples in separate storage, and new monitor kinds whose evaluator writes normalized results to `measurement`. **Invariant:** organization → project → monitor → measurement → incident ownership, composite FKs, the permission matrix and the SYSTEM_ADMIN boundary do not change.

### ADR-010 SSRF policy in code; pinned IP; no redirect following
**Decision:** destination policy is code, applied on every attempt: strict URL parsing, ports 80/443, full A/AAAA validation (any forbidden answer blocks), connection pinned to the validated IP with Host/SNI/certificate verification preserved, `trust_env=False`, redirects not followed (3xx recorded as status), egress firewall as defense in depth. No user, role or SYSTEM_ADMIN setting can allow private, loopback or metadata targets. The dev fixture policy cannot start outside development/test. **Revisit:** per-hop validated redirect following (OD-06, P1).

### ADR-011 Domain ownership verification before activation
**Decision:** monitors stay DRAFT until a DNS TXT proof covers the hostname (FQDN and subdomains, re-verified every 30 days) or a SYSTEM_ADMIN exception is active. **Rationale:** stops SentinelOps from being used to probe or load third-party services. The draft required this, but the brief does not mention it, so it is listed as OD-05. **Consequence:** adds onboarding friction; exceptions cover demo targets.

### ADR-012 Scheduling, concurrency, retries and result semantics
**Decision:** workers claim due rows with leases sized to the worst-case check duration. Cadence is fixed with initial jitter and missed-slot skipping. Generations discard stale completions. Bounded global, per-org and per-host concurrency. In-check retries apply only to transient network categories and re-validate DNS on each attempt. Results are PASS/SLOW/FAIL/BLOCKED/INCONCLUSIVE, and only scheduled conclusive results drive health. Check-now never affects health. Staleness turns health UNKNOWN. **Rationale:** clear semantics prevent false UP, alert storms from probe-side faults, and duplicate incidents.

### ADR-013 Incident transition and outbox in one transaction
Measurement insert, health update, incident/event creation and outbox insert commit atomically. The notifier delivers at least once, using dedupe keys and incident references.

### ADR-014 Email through platform relay; Telegram fixed host
**Decision:** organizations do not configure SMTP hosts. Email alerts go through the platform SMTP relay to ACTIVE members of the organization. Telegram uses an organization bot token, sent only to the fixed Bot API host. **Rationale:** the draft's org-supplied SMTP credentials would let tenants make the notifier connect to arbitrary hosts (an SSRF vector) and complicate secret handling. **Revisit:** external recipients (OD-08); webhooks in P1 must reuse the SSRF policy.

### ADR-015 Application-level secret encryption bound to organization
AES-256-GCM with a key ring. Associated data binds organization, table, row and field. Rotation re-encrypts in batches. Encrypted fields: monitor URL, custom headers, Telegram token and chat ID. Headers and Telegram credentials are write-only in every API. The monitor URL is encrypted at rest but returned decrypted only to `MON.update` holders in the edit form (`PERMISSION_MATRIX.md` §5).

### ADR-016 Opt-in, snapshot-based public status pages
Pages are disabled by default. The public endpoint reads only allowlisted snapshot JSON, never private tables. Public incident titles are generic.

### ADR-017 Default monitoring parameters
Interval 60 s (allowed 60/120/300), timeout 10 s (3–15 s), failure threshold 3, recovery threshold 2, retry attempts 1, TLS warning 14 days, default 20 monitors per organization, check-now 1/monitor/60 s and 30/org/hour. Platform settings may tighten or adjust limits within schema CHECK ranges. **Revisit:** OD-15.

### ADR-018 Server-side session cookies, not JWT
Opaque tokens stored hashed allow immediate revocation (membership removal, password reset, SYSTEM_ADMIN deactivation). Used together with CSRF tokens.

### ADR-019 Unified measurement model
The draft's `probe_run` is merged into `measurement` (job ID, trigger, source kind, schema version), and the lease lives on `monitor_schedule`. This gives one canonical result table for Phase 1 probes and Phase 2 evaluator outputs, and one fewer write per check.

### ADR-020 Organization suspension semantics
Suspended organization: members get 403 `ORG_SUSPENDED`; claims stop; pending notifications are cancelled, not delayed (avoids stale alert bursts on reactivation); the public page returns 404; data is retained. On activation, health resets to UNKNOWN and generation increments. **Revisit:** read-only access during suspension (OD-03).

### ADR-021 Custom request headers in Phase 1
**Context:** the brief refers to "private authentication headers" as organization secrets, which implies monitors may carry them. The draft disallowed arbitrary headers. **Decision:** up to 5 headers, deny-listed names, encrypted names and values, write-only, GET/HEAD with no request body. **Revisit:** OD-07.

### Draft v0.1 ADR mapping
Draft ADR-001 (PostgreSQL queue) → ADR-001; ADR-002 (verified domains) → ADR-011; ADR-003 (GET/HEAD, no redirects) → ADR-010/ADR-021; ADR-004 (pinned IP, egress firewall) → ADR-010; ADR-005 (event/outbox transaction) → ADR-013; ADR-006 (org-scoped membership, composite constraints) → ADR-003/ADR-004; ADR-007 (Alloy future) → ADR-009; ADR-008 (status pages opt-in) → ADR-016; ADR-009 (3/2 thresholds) → ADR-017; ADR-010 (DB leases) → ADR-012. All draft entries are superseded by the records above.

## 3. Open decisions register
Each open decision has a default that the baseline documents already implement consistently. The PO confirms the default or chooses an alternative **before the listed gate starts**. Changing a default requires updating the referenced documents and a baseline version bump.

**Closure record, 31 Oct 2026 (PO approval of G0):** all open decisions OD-01…OD-15 are **closed with their baseline defaults accepted**, subject to the existing baseline and security constraints. The MVP scope is unchanged. Explicit confirmations:
- **OD-05:** DNS TXT domain verification is required before a monitor can leave DRAFT and be scheduled (FR-MON-003). SYSTEM_ADMIN exceptions stay as specified in FR-PLT-009 and never bypass the SSRF policy.
- **OD-07:** up to five custom HTTP request headers per monitor, encrypted at rest (names and values), and never exposed in API responses, logs, alerts/notifications, exports, audit entries, the SYSTEM_ADMIN console or public status pages (FR-MON-014, ADR-021, AC-028).
- **OD-01:** SYSTEM_ADMIN MFA is not part of the local MVP and is mandatory before any non-local deployment (re-checked at G7).
- **OD-12:** no break-glass access in the MVP; any future support-access feature needs a new ADR.

| ID | Question | Baseline default | Alternatives | Must close before | Affects | Status |
|---|---|---|---|---|---|---|
| OD-01 | MFA for SYSTEM_ADMIN accounts? | Not in local MVP; **mandatory before any non-local deployment** | TOTP required from G1 | G1 (MVP scope); G7 (deployment) | SRS FR-ID-001, FR-PLT-001 | Closed 31 Oct 2026: default accepted |
| OD-02 | Self-service organization creation? | No; SYSTEM_ADMIN creates organizations | Public signup with quotas and abuse controls | G2 | ADR-008, FR-ID-001, FR-ORG-006 | Closed 31 Oct 2026: default accepted |
| OD-03 | Member access while organization is suspended? | Fully blocked (403) | Read-only access/export for ORG_OWNER | G2 | ADR-020, FR-PLT-004 | Closed 31 Oct 2026: default accepted |
| OD-04 | May ORG_MEMBER create/edit monitors? | No (draft "Responder" scope) | Allow create/edit without secret headers | G2 | PERMISSION_MATRIX MON.* | Closed 31 Oct 2026: default accepted |
| OD-05 | Is domain verification mandatory? | Yes: DNS TXT, covers subdomains, 30-day re-verification, SYSTEM_ADMIN exceptions | Optional, or HTTP file proof | G3 | ADR-011, FR-MON-003 | Closed 31 Oct 2026: default accepted |
| OD-06 | Follow redirects? | No; 3xx recorded as status | Follow ≤ 3 hops with per-hop validation (P1) | G3 | ADR-010, FR-MON-004 | Closed 31 Oct 2026: default accepted |
| OD-07 | Custom request headers in Phase 1? | Yes: ≤ 5, encrypted, write-only | None in Phase 1 | G3 | ADR-021, FR-MON-014 | Closed 31 Oct 2026: default accepted |
| OD-08 | Email alerts to non-member addresses? | No; ACTIVE members only | Confirmed external addresses (double opt-in) | G5 | ADR-014, FR-NTF-001 | Closed 31 Oct 2026: default accepted |
| OD-09 | PostgreSQL RLS as defense in depth? | Not in Phase 1 | Enable RLS with `SET LOCAL app.org_id` per transaction | G2 | ADR-003 | Closed 31 Oct 2026: default accepted |
| OD-10 | Retention periods | Raw 30 days; rollups, incidents, audit 12 months | Per-org or compliance-driven | G6 | NFR-006 | Closed 31 Oct 2026: default accepted |
| OD-11 | Organization offboarding: deletion and data export | No hard delete in Phase 1; suspend only | SYSTEM_ADMIN delete after owner-confirmed export | G7 | FR-PLT-003 | Closed 31 Oct 2026: default accepted |
| OD-12 | SYSTEM_ADMIN break-glass access to org data | None; invitation by the org only | Time-boxed, owner-approved, audited support access | Post-MVP | ADR-005 | Closed 31 Oct 2026: default accepted |
| OD-13 | May SYSTEM_ADMIN disable global user accounts? | No in Phase 1 (suspend org instead) | Lock account and revoke sessions, audited | G2 | PERMISSION_MATRIX PLT.user.disable | Closed 31 Oct 2026: default accepted |
| OD-14 | Final product name and branding | "SentinelOps" working title | — | Non-blocking | — | Closed 31 Oct 2026: default accepted |
| OD-15 | Default platform limit values | ADR-017 values | Other values | G3 | ADR-017, platform_settings | Closed 31 Oct 2026: default accepted |

## 4. Contradictions found in draft v0.1 and their resolution
| # | Draft issue | Resolution |
|---|---|---|
| C-01 | Roles "Platform Operator" and "Responder" differ from the approved roles | SYSTEM_ADMIN and ORG_MEMBER (ADR-005, ADR-007) |
| C-02 | `session.selected_org_id` plus `/orgs/{org}` paths: ambiguous authorization source | Path is authoritative; preference only (ADR-004) |
| C-03 | "Owner creates org" (journey 1) vs. invite-only accounts; no rule for who creates orgs | SYSTEM_ADMIN creates (ADR-008) |
| C-04 | Org-supplied SMTP credentials create notifier SSRF exposure | Platform relay (ADR-014) |
| C-05 | Composite FKs missing for assignee, outbox→channel, route→project/monitor; `UNIQUE(org,id)` missing on most parents | Added (DB §2, §4) |
| C-06 | `probe_run` and `measurement` duplicate job state | Merged (ADR-019) |
| C-07 | Kickoff prompt referenced `docs/01_SRS.md` (wrong path) | Fixed to `docs/baseline-v1.0/…` |
| C-08 | Monitoring gate (G2) preceded org management and had no admin gate | New G1 (identity + admin), G2 (orgs), G3+ monitoring |
| C-09 | HEAD method combined with response-body validation | Validation requires GET (DB CHECK) |
| C-10 | Manual resolution "optionally reopening" undefined | Manual resolve rejected while DOWN; no reopen (FR-INC-004) |
| C-11 | No check-result semantics for policy blocks or probe faults | BLOCKED/INCONCLUSIVE defined (FR-MON-012) |
| C-12 | "Expired TLS → separate alert" vs. TLS verification failing the check | Both: FAIL (TLS_ERROR) plus TLS_EXPIRY incident (FR-MON-007) |
| C-13 | Monitor `state` and `enabled` both present, with PAUSED as a health state | Lifecycle vs. health split (FR-MON-009) |
| C-14 | Check-now path vs. "only scheduled results influence transitions" unclear | MANUAL trigger excluded from health (FR-MON-008) |
| C-15 | No password reset, platform email or invitation delivery defined | FR-ID-006, FR-ID-007 |
| C-16 | Suspension, platform limits and admin management absent | FR-PLT-003…009 |
| C-17 | NFR-009 "IP-resolved secrets" ambiguous | Resolved IPs never persisted |
| C-18 | Separate `scheduler` and `probe-worker` services | Single `worker` claims and probes (ADR-001) |

## 5. Implementation clarifications
Values the baseline left open, fixed during implementation and accepted by the PO. They clarify, and do not change, approved functionality.

| ID | Clarification | Accepted |
|---|---|---|
| IC-01 | Password policy: 12–128 characters; must not contain the email local part (when it has ≥ 4 characters); not a single repeated character or a listed common password (FR-ID-001) | 31 Oct 2026 (G2 approval) |
| IC-02 | Sessions: 8-hour idle timeout and 24-hour absolute lifetime, both configurable (FR-ID-001) | 31 Oct 2026 (G2 approval) |
| IC-03 | SYSTEM_ADMIN invitations expire after 24 hours (FR-PLT-005) | 31 Oct 2026 (G2 approval) |
| IC-04 | Platform settings defaults: 3 status pages and 10 notification channels per organization, in addition to the ADR-017 values (FR-PLT-008) | 31 Oct 2026 (G2 approval) |
| IC-05 | `auth_throttle` is an approved G1 security-support table for login throttling and lockout (FR-ID-001; `03_DATABASE_DESIGN.md` §2.1) | 31 Oct 2026 (G2 approval) |
| IC-06 | Domain verification: a pending DNS challenge is valid 7 days and its value is shown only when issued (hash stored; regenerate if lost); proofs are re-checked from 3 days before their 30-day expiry; status `REVOKED` added for organization-initiated revocation (FR-MON-003) | 31 Oct 2026 (G4 approval) |
| IC-07 | SYSTEM_ADMIN domain exceptions default to 90 days (1–365) (FR-PLT-009). Safeguards: each exception names one explicit FQDN scope (covering its subdomains, like a DNS proof), requires the organization's written justification (10–500 characters), always has an expiry, and is audited when requested and decided. An exception only replaces ownership proof: it never bypasses the DNS destination/IP restrictions or the SSRF policy (FR-MON-004) | 31 Oct 2026 (G4 approval) |
| IC-08 | G3 maintains the health counters (`consecutive_*`) from eligible scheduled results; health `state` transitions are applied by the G4 state machine (FR-MON-012, FR-INC-001) | 31 Oct 2026 (G4 approval) |
| IC-09 | Worker defaults: concurrency 50, per-organization 10, per-host 2, idle wait ≤ 5 s (bounds check-now latency), shutdown grace 60 s, initial jitter ≤ 60 s; all configurable (FR-MON-005). These limits are enforced **per worker process**; there is no global enforcement across workers. The MVP-supported topology is a single worker process | 31 Oct 2026 (G4 approval) |
| IC-10 | Probes send a fixed User-Agent and `Accept-Encoding: identity`; both join the custom-header deny-list; validation reads raw bytes up to the cap, and JSON validation of a truncated body is `RESPONSE_TOO_LARGE` (FR-MON-013/014) | 31 Oct 2026 (G4 approval) |
| IC-11 | The `dev-fixtures` probe policy additionally permits loopback only (metadata and private ranges stay blocked) and is refused outside development/test (FR-MON-004) | 31 Oct 2026 (G4 approval) |
| IC-12 | Schema details: `monitor.tags_json`, `monitor.header_key_id`, `monitor_schedule.current_trigger` and `last_manual_check_requested_at`; measurements are append-only for the app role (no UPDATE; DELETE is granted with the G6 retention job) | 31 Oct 2026 (G4 approval) |
| IC-13 | Event foundation (ADR-013): every incident change appends one `incident_event` in the same transaction (OPENED, ACKNOWLEDGED, ASSIGNED, UNASSIGNED, COMMENTED, RESOLVED); OPENED/ACKNOWLEDGED/RESOLVED are unique per incident in the database. `notification_outbox` references a channel, so it is created with the channels in G5 (migration `0006_notifications`), and G5 inserts outbox rows from the same event write path and transaction. G4's migration is `0005_incidents` | 31 Oct 2026 (G5 approval) |
| IC-14 | Health state machine details (Architecture §6): counters are PASS/SLOW successes, PASS-only passes (new column `monitor_health.consecutive_passes`, used for `DEGRADED → UP`), SLOW and FAIL; at most one transition per result; a result older than the newest applied one is ignored. While an OUTAGE incident is still active and health is UNKNOWN (after staleness, edit, pause/resume or activation), recovery needs `recovery_threshold` successes rather than one. Staleness also resets the counters so fresh evidence is required; it never resolves incidents | 31 Oct 2026 (G5 approval) |
| IC-15 | Incident presentation: severity CRITICAL for OUTAGE and WARNING for TLS_EXPIRY; generic titles ("Outage detected", "TLS certificate expiring"); timeline evidence holds only result, failure category, HTTP status, response time, attempt count, observation time and certificate expiry (never URL, host, query string, headers, body or IP) | 31 Oct 2026 (G5 approval) |
| IC-16 | Incident operations: acknowledging an acknowledged incident is a no-op; assignment accepts any ACTIVE member (or unassign); suspending/removing a member or leaving unassigns their unresolved incidents with a SYSTEM event; notes are plain text up to 2000 characters and are also allowed on resolved incidents; mutations accept an optional `version` (409 `VERSION_CONFLICT`); manual resolution of OUTAGE is refused (409 `OUTAGE_STILL_DOWN`) only while the monitor is ACTIVE and DOWN; manual resolution of TLS_EXPIRY is allowed, and a new incident opens on the next scheduled check if the certificate is still below the threshold | 31 Oct 2026 (G5 approval) |
| IC-17 | TLS expiry evaluation uses only certificate expiry already captured by scheduled PASS/SLOW/FAIL checks (no extra probes). Results without certificate data (HTTP monitors, connection or TLS handshake failures) leave TLS_EXPIRY unchanged. An expired or invalid certificate fails verification, so it is reported as FAIL `TLS_ERROR` (and OUTAGE after the failure threshold); the TLS_EXPIRY incident normally opened earlier from the warning window | 31 Oct 2026 (G5 approval) |
| IC-18 | Telegram follows the baseline (FR-NTF-001, ADR-014): each organization supplies its own bot token and chat ID, sealed together and write-only. Setup is verified with a test message, which the notifier delivers (the API makes no outbound calls). A platform-managed bot with chat linking was considered and declined by the PO for Phase 1 | 31 Oct 2026 (G6 approval) |
| IC-19 | Delivery policy (FR-NTF-003/004): 300 s leases; at most 8 attempts, including reclaimed crashed leases; backoff 30 s × 2^(n−1), capped at 1 h, plus up to 20 % jitter; Telegram `retry_after` honoured (≤ 1 h); temporary errors (timeouts, network errors, 5xx, 429, SMTP 4xx) retry, while permanent ones (Telegram 400/401/403/404, SMTP 5xx or refused recipient) fail immediately. Per-channel limit of 20 sends per minute across notifiers: excess items are deferred without using an attempt. The per-incident throttle is one message per lifecycle event per channel (dedupe key). Superseded items are cancelled: opened or acknowledged notices for an incident already resolved, and auto-pause notices for a monitor already resumed. Delivery is at-least-once: a crash after a provider accepted a message can resend it. Email retries skip recipients already sent | 31 Oct 2026 (G6 approval) |
| IC-20 | Notification events: INCIDENT_OPENED (OUTAGE), TLS_EXPIRY_WARNING (TLS_EXPIRY opened), INCIDENT_ACKNOWLEDGED, INCIDENT_RESOLVED, MONITOR_AUTO_PAUSED, plus internal CHANNEL_TEST. Assignments and notes do not notify. Auto-pause email goes only to recipients who are ORG_OWNER/ORG_ADMIN (FR-MON-012). A new channel can optionally get an organization-wide all-events route. Channel tests are limited to 1 per minute per channel; email channels take 1–50 recipients. Schema additions: outbox `lease_token`, `last_result_code`, `created_at`, `sent_at`; delivery `recipient_user_id`; channel `created_by` and timestamps | 31 Oct 2026 (G6 approval) |
| IC-21 | Status pages (FR-UI-004, ADR-016): a user-chosen global slug (3–40 lowercase letters, digits or hyphens). The public snapshot allowlist is: page title; overall status; per component, its public name, status and availability over 24 h/7 d (scheduled conclusive checks, as defined in IC-23); and OUTAGE incidents only, with the generic title "Service disruption" (active ones, plus those resolved in the last 7 days). TLS warnings, hosts, URLs, monitor names, notes, assignees and evidence are never public. Paused/draft monitors show UNKNOWN; archived monitors are hidden. Snapshots are rebuilt on every change and every 60 s by the worker. Publishing and unpublishing are separate STP.publish endpoints. Public responses are cacheable for 30 s; 404s are `no-store`. The public endpoint allows 120 requests per minute per client IP, per API process (the socket peer; proxy-aware IP remains a known gap). At most 50 monitors per page | 31 Oct 2026 (G6 approval) |
| IC-22 | G5 migrations are `0006_notifications` and `0007_status_pages`. The platform read views planned for `0007` move to the G6 platform-dashboard migration | 31 Oct 2026 (G6 approval) |
| IC-23 | Report definitions (FR-UI-006, AC-013, DB §8). Known limitations: coverage uses each monitor's *current* interval, so it is approximate across interval changes; latency percentiles for windows older than raw retention combine hourly percentiles and are approximate. Only SCHEDULED results count. Uptime = (PASS + SLOW) / (PASS + SLOW + FAIL), shown as "no data" (never 100 %) without conclusive samples. Coverage = conclusive / expected slots, where expected = time since the later of window start and monitor creation, divided by the current interval; paused time, missed slots, BLOCKED and INCONCLUSIVE are coverage gaps. Estimated downtime = FAIL samples × interval; outage time = overlap of OUTAGE incidents (detection to recovery); both are labelled estimates. Latency is nearest-rank p50/p95 over PASS/SLOW samples: exact within raw retention, otherwise combined hourly percentiles labelled approximate. Presets cover (now − 24 h/7 d/30 d, now]. Custom ranges are whole local days in the organization's timezone (DST-aware), up to 366 days. Buckets are hourly for windows up to 48 h, otherwise local days. Each hour is counted once: from its rollup if fully inside the window, else from raw. CSV export streams the per-monitor aggregates with formula-injection escaping | 1 Nov 2026 (G7 approval) |
| IC-24 | Rollups and retention (NFR-006, OD-10): an advisory-locked worker task every 5 minutes recomputes the last 3 closed UTC hours (5-minute grace), which absorbs late results (at most one lease late). Retention first rolls up every expiring hour that lacks a rollup, then deletes raw rows older than the hour boundary 30 days back, in batches of 5000; manual check results expire without aggregation. Rollups are kept 12 months. Incidents, audit and notification history are not purged in Phase 1: the 12-month figure is a minimum, and purging is an operational decision after the MVP. The app role gains DELETE on `measurement` and `hourly_monitor_rollup` only | 1 Nov 2026 (G7 approval) |
| IC-25 | Realtime (FR-UI-005, ADR-001): SSE at `GET /api/orgs/{org}/events` (RPT.dashboard), fed by transactional `pg_notify` and one LISTEN connection per API process. Events: `check.recorded`, `monitor.health`, `monitor.lifecycle` (auto-pause), `incident.*` (each timeline event) and `notification.delivery`; payloads carry IDs, states and result codes only. Membership, organization status and the login session are re-validated every 15 s (the stream ends with `revoked`). Heartbeats every 15 s; streams end after 5 minutes with `reconnect`. Per-subscriber queues are bounded; on overflow or listener reconnect the client gets `resync`. The client refetches its snapshot on every (re)connect and event; there is no replay | 1 Nov 2026 (G7 approval) |
| IC-26 | Platform read model (DB §5, FR-PLT-002/006): a third aggregate view, `v_platform_queue_health`, alongside `v_platform_org_summary` and `v_platform_usage_daily`. It provides claim backlog/lag, checks in flight, check volume and outbox backlog/lag/failures without the platform plane reading private tables. The organization summary adds open-incident counts by severity (counts only). Workers count as alive with a heartbeat within 90 s; checks per minute = checks in the last 15 minutes / 15 | 1 Nov 2026 (G7 approval) |
| IC-27 | G6 migration `0008_platform_views`: the three views, indexes `measurement(observed_at)` and `hourly_monitor_rollup(window_start)` for retention batches, and the IC-24 DELETE grants. No new tables. Status-page availability (IC-21) keeps its raw-measurement computation, which within raw retention matches the IC-23 definition | 1 Nov 2026 (G7 approval) |
| IC-28 | SYSTEM_ADMIN MFA (OD-01): TOTP (RFC 6238, SHA-1, 6 digits, 30 s, ±1 step) with replay protection (a code's step must be newer than the last accepted one), and 10 single-use recovery codes stored as SHA-256 hashes. TOTP secrets are AES-256-GCM sealed with a dedicated key ring (`SENTINELOPS_MFA_KEYS`), separate from organization secrets, and bound to the user. Policy: required in production (the app refuses to start without MFA keys), configurable otherwise. Login creates a `VERIFY` (or `ENROLL`) session that reaches only `/api/auth/me`, `/logout` and `/mfa/*`; success rotates the session. Enrolment, recovery-code replacement and disabling require the password (and a code); disabling is refused while required. Failures count against the login throttle; 5 failures revoke the pending session. Lost devices: `sentinelops reset-admin-mfa` (host shell, audited). Member MFA remains out of Phase 1 scope (FR-ORG-006) | 1 Nov 2026 (post-G7 PO confirmation) |
| IC-29 | Client IP: `X-Forwarded-For` is honoured only when the socket peer is in `SENTINELOPS_TRUSTED_PROXIES`, reading right to left past trusted hops; otherwise the peer is the client. Uvicorn's own proxy-header handling is disabled. It applies to login throttling and the public status-page rate limit | 1 Nov 2026 (post-G7 PO confirmation) |
| IC-30 | Egress: the probe worker keeps its G3 firewall (public destinations only; the SSRF policy in code decides what may be contacted). The notifier gets a default-deny firewall: the database, the configured SMTP relay, Telegram's published Bot API ranges on 443 and DNS only; IPv6 denied; it fails closed without NET_ADMIN. Both drop to uid 10001. Validated in local containers; the Telegram ranges are configuration (`SENTINELOPS_EGRESS_ALLOW_CIDRS`) and must be reviewed against Telegram's published list before deployment. Cloud firewall rules are a deployment task | 1 Nov 2026 (post-G7 PO confirmation) |
| IC-31 | Release tooling: Playwright E2E runs the real API through a test-only harness (`apps/api/tests/e2e/server.py`, never packaged) with fake DNS, probes, email and Telegram against the guarded `sentinelops_test`; CI runs Chromium (desktop + mobile), and WebKit is supported locally via `E2E_WEBKIT=1`. The opt-in demo seed (`sentinelops seed-demo --confirm`) writes only to an empty `*_demo` database, generates passwords and prints them once, and schedules demo monitors far in the future so they are never probed. Production deployment is a single-host Compose file with Caddy (HTTPS, security headers), a manual migrate job, a least-privilege app login role and backup/restore scripts | 1 Nov 2026 (post-G7 PO confirmation) |
