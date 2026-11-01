# SentinelOps — Agentless API Monitoring & Incident Management
## Software Requirements Specification · Baseline v1.0 · 31 Oct 2026

**Status:** Baseline v1.0. Incorporates the Product Owner decision brief of 31 Oct 2026 (multi-tenancy, SYSTEM_ADMIN, organization roles, agentless Phase 1, future Grafana Alloy, technology stack). Defaults adopted where the brief is silent are recorded as open decisions (OD-xx) in `ARCHITECTURE_DECISIONS.md` §3, each with the gate by which it must be confirmed. Document precedence: `README_DOCUMENTS.md`.

**Product positioning:** multi-tenant, language-agnostic synthetic API monitoring and incident management SaaS. **Phase 1:** agentless public HTTP/HTTPS checks. **Phase 2:** Grafana Alloy host metrics (not implemented now; interfaces only). **Phase 3:** traces and advanced analysis.

## 1. Objectives and success criteria
Give engineering teams one place to understand whether authorized services are reachable, how quickly they respond, what failed, who was alerted and when recovery occurred. Target a working local Docker Compose demonstration using fictional organizations and endpoints, with deployable configuration but no public deployment by default.

**MVP acceptance:** (1) two organizations cannot view or influence each other's data through the API, workers, notifications, exports, realtime events or status pages; (2) the platform is bootstrapped with a SYSTEM_ADMIN without any default credentials, and SYSTEM_ADMIN cannot read organization secrets; (3) organization roles are enforced exactly as in `PERMISSION_MATRIX.md`; (4) a monitor can check an explicitly authorized public endpoint on schedule; (5) repeated failures open one incident and recovery resolves it; (6) notifications are deduplicated and retried; (7) historical uptime/latency, reports and a sanitized public status page are available; (8) SSRF and credential-leak controls pass adversarial tests; (9) end-to-end browser journeys pass.

## 2. Users, planes and roles
Authorization has two **separate planes**. A role in one plane never grants anything in the other (ADR-005).

**Platform plane**
- **SYSTEM_ADMIN:** operates the platform: platform dashboard, organization lifecycle (create, rename, activate, suspend), platform administrator accounts, aggregate usage and health, platform limits and operational settings, domain-verification exceptions. Sees organization **metadata only** (Section 3.2, FR-PLT-006). Has no implicit organization membership, cannot impersonate users and has no API path to decrypt organization secrets (monitor URLs, request headers, notification credentials). To work inside an organization a SYSTEM_ADMIN must be invited as a normal member by that organization, which is visible and audited. The initial SYSTEM_ADMIN is the platform owner, created through the bootstrap process (FR-PLT-001).

**Organization plane** (per membership; one global user may hold different roles in different organizations)
- **ORG_OWNER:** full control of the organization, including ownership and owner/admin role assignment.
- **ORG_ADMIN:** manages projects, monitors, monitor secrets, notification channels/routes, status pages, and members holding ORG_MEMBER or VIEWER.
- **ORG_MEMBER:** operational responder: views monitoring data and monitor configuration (display URL without query string; never header values), runs check-now, acknowledges/assigns/comments/resolves incidents, exports reports. Cannot change monitor configuration, secrets, notification settings or members (OD-04).
- **VIEWER:** read-only dashboards, monitors (display name and host only), incidents and reports.
- **Anonymous visitor:** sees only explicitly published status-page content. Never sees private URLs, headers, internal names, incident notes or other sensitive details.

The authoritative permission matrix is `PERMISSION_MATRIX.md`. Where this section and the matrix differ, the matrix wins and the difference is a defect.

## 3. Functional requirements
Identifiers are stable across versions; retired IDs are not reused. P0 = mandatory MVP, P1 = after MVP.

### 3.1 Identity, sessions and organization context
- **FR-ID-001 P0:** No public self-registration (ADR-008). Accounts are created only by bootstrap (FR-PLT-001), platform admin invitation or organization invitation. Login/logout, Argon2id password hashing, opaque server-side sessions in HttpOnly/Secure/SameSite cookies, CSRF protection on all mutations, login throttling and session rotation on login and privilege change.
- **FR-ID-002 P0:** Organization invitations: single-use, hashed token, bound to an email address, expire after 7 days, carry a role the inviter is allowed to assign (FR-ORG-003). Accepting creates the account if needed and an ACTIVE membership.
- **FR-ID-003 P0:** Every tenant-owned row carries `organization_id` and every tenant query is scoped by it. A user who is not an ACTIVE member of the organization in the request, or who requests a resource belonging to another organization, receives `404` (non-disclosing). An ACTIVE member lacking the permission receives `403`.
- **FR-ID-004 P0:** Audit privileged changes, platform actions and incident actions without storing secrets (FR-PLT-007).
- **FR-ID-005 P0:** Organization switching: the user lists their memberships and selects an organization. The organization ID in the API path is the only authorization context; it is re-validated against `organization_member` on **every** request. The session's last-selected organization is only a UI preference and is never used for authorization. On switch, the client discards cached data and realtime streams for the previous organization.
- **FR-ID-006 P0:** Password reset through a single-use, hashed, 30-minute email token. Reset revokes all of the user's sessions.
- **FR-ID-007 P0:** Platform transactional email (invitations, activation, reset) is sent through the platform-configured SMTP relay. In local development a mail-catcher container is used; no real recipients.

### 3.2 Platform administration (SYSTEM_ADMIN)
- **FR-PLT-001 P0 — Bootstrap:** The first SYSTEM_ADMIN is created by an operator running a one-time CLI command inside the deployment (`bootstrap-system-admin --email <address>`). The command refuses to run if any SYSTEM_ADMIN exists, creates the account with **no password**, and prints a single-use activation link with a token that expires after 30 minutes. The token is stored only as a hash. The owner sets their password through the link. No hardcoded passwords, default accounts, credential environment variables or seed users exist in any environment. The bootstrap is audited. Recovery when every SYSTEM_ADMIN is locked out uses the same CLI with an explicit `--recover` flag. It requires host shell access, issues an activation token for an existing SYSTEM_ADMIN and is audited.
- **FR-PLT-002 P0 — Platform dashboard:** organizations by state, total and active monitors, checks per minute, worker claim lag and backlog, outbox backlog and failed deliveries, per-organization usage against limits, recent platform audit events.
- **FR-PLT-003 P0 — Organization lifecycle:** create an organization (name, slug, timezone) and invite its initial ORG_OWNER by email. A SYSTEM_ADMIN may issue further owner invitations **only while the organization has no ACTIVE ORG_OWNER** (e.g. the invitation expired), so that platform admins cannot grant themselves access to an owned organization. Rename, set limits, suspend (with a reason) and activate. Phase 1 has no hard delete (OD-11).
- **FR-PLT-004 P0 — Suspension semantics:** for a SUSPENDED organization, all organization-plane API and SSE access returns `403 ORG_SUSPENDED` to members. Workers claim no monitors. Pending notifications are cancelled, not delayed. The public status page returns `404`. Data is retained. Activation restores access; monitors resume with health reset to UNKNOWN and a new schedule generation (OD-03).
- **FR-PLT-005 P0 — Platform administrators:** invite another SYSTEM_ADMIN (single-use, expiring invitation) and deactivate a SYSTEM_ADMIN. The last active SYSTEM_ADMIN cannot be deactivated. A SYSTEM_ADMIN cannot deactivate themself. Deactivation revokes that user's platform-plane access immediately. Their organization memberships, if any, are unaffected.
- **FR-PLT-006 P0 — Metadata-only visibility:** SYSTEM_ADMIN may view organization name, slug, state, timestamps, owner contact emails, member/project/monitor/status-page counts, check volume, incident counts, usage against limits, verified domain names and pending domain-exception requests. SYSTEM_ADMIN may **not** view monitor names, hosts or URLs, request header names or values, response-validation rules, notification channel configuration, incident content, member lists beyond owner contacts, or any decrypted secret. No break-glass access exists in Phase 1 (OD-12).
- **FR-PLT-007 P0 — Audit:** platform actions are recorded in `audit_event` with scope PLATFORM. Actions that affect an organization (create, suspend, activate, limit change, domain exception) also carry that `organization_id` and are visible to the organization's ORG_OWNERs.
- **FR-PLT-008 P0 — Limits and settings:** platform defaults (max monitors per organization, minimum interval, max timeout, max retry attempts, max custom headers, check-now rate limits, max status pages, max notification channels, response validation byte cap) with optional per-organization overrides. Limits are enforced on the server inside the mutating transaction. SSRF policy is **not** a setting: no SYSTEM_ADMIN setting can relax the destination deny-list (ADR-010).
- **FR-PLT-009 P0 — Domain exceptions:** a SYSTEM_ADMIN may approve an organization's request to monitor a hostname without DNS proof (method ADMIN_EXCEPTION, with expiry and reason, audited). Exceptions never bypass the SSRF deny-list.

### 3.3 Organizations and membership
- **FR-ORG-001 P0:** Roles ORG_OWNER, ORG_ADMIN, ORG_MEMBER, VIEWER. Membership status is ACTIVE, SUSPENDED or REMOVED and is independent per organization. Only ACTIVE memberships grant access. Removal is soft (row retained for audit and assignment history).
- **FR-ORG-002 P0:** The last ACTIVE ORG_OWNER cannot be removed, suspended, demoted or leave. This is enforced in one transaction that locks the organization row, so concurrent changes cannot leave zero owners.
- **FR-ORG-003 P0:** Role assignment rule: ORG_OWNER may assign any role. ORG_ADMIN may invite, change, suspend or remove only ORG_MEMBER and VIEWER memberships and may grant only those roles. Nobody may change their own role except an ORG_OWNER stepping down while another ACTIVE ORG_OWNER exists. Ownership transfer = promote another member to ORG_OWNER, then step down.
- **FR-ORG-004 P0:** Membership change, suspension or removal takes effect on the next request. Open SSE streams for that membership are closed within 30 seconds. Assigned incidents of a removed member are unassigned.
- **FR-ORG-005 P0:** Organization settings (name, timezone) editable per `PERMISSION_MATRIX.md`. Organization state (ACTIVE/SUSPENDED) is changed only by SYSTEM_ADMIN.
- **FR-ORG-006 P1:** Self-service organization creation (OD-02), member-level MFA, SSO.

### 3.4 Monitor management
- **FR-MON-001 P0:** Projects group monitors within an organization: name, description, archived status.
- **FR-MON-002 P0:** Create/edit/pause/resume/archive an HTTP or HTTPS monitor: display name, URL, method GET or HEAD, interval 60/120/300 s (not below the effective minimum interval), timeout 3–15 s, expected status set (codes and ranges, default 200–299), optional response validation (FR-MON-013), optional custom request headers (FR-MON-014), latency threshold for DEGRADED, failure/recovery thresholds, retry attempts (FR-MON-011), TLS expiry warning threshold, tags and owning project.
- **FR-MON-003 P0:** A monitor stays in lifecycle DRAFT until its hostname is covered by a valid `verified_domain` for the same organization (DNS TXT proof covering the FQDN and its subdomains, re-verified every 30 days) or an active SYSTEM_ADMIN exception (FR-PLT-009) (OD-05). Coverage is re-checked at claim time.
- **FR-MON-004 P0:** SSRF policy, applied on every attempt, including retries and check-now: scheme http/https only; ports 80 and 443 only; no userinfo, fragments or IP-literal hosts; resolve all A/AAAA answers and reject the target if **any** answer is in a forbidden range (loopback, RFC 1918, CGNAT 100.64/10, link-local incl. 169.254.169.254, unique-local, multicast, unspecified, broadcast, documentation, benchmarking, reserved, IPv4-mapped/compatible/NAT64/6to4 forms of these, and cloud metadata addresses); connect only to the validated IP while preserving Host and TLS SNI with certificate verification; ignore proxy environment variables; **do not follow redirects** (a 3xx is recorded as the response status) (OD-06). Ordinary users, ORG roles and SYSTEM_ADMIN have no way to permit private, loopback or metadata destinations. A development-only fixture policy exists solely through deployment configuration that the application refuses to start with outside `ENV=development|test`.
- **FR-MON-005 P0:** Scheduled checks run only in worker processes, never in API request handlers. At most one active lease per monitor, bounded concurrency (global per worker, per organization, per destination host), fixed cadence with initial jitter, and per-check deadline (Section 3.5).
- **FR-MON-006 P0:** Each check records: result (FR-MON-012), failure category, HTTP status, elapsed time, attempt count, TLS certificate expiry, trigger (SCHEDULED/MANUAL) and observation time. URLs with query strings, headers, response bodies and resolved IPs are never written to measurements, logs, incidents or notifications.
- **FR-MON-007 P0:** For HTTPS monitors, each check captures certificate expiry. When remaining validity falls below the warning threshold (default 14 days), a TLS_EXPIRY incident opens, separate from availability. An invalid or expired certificate also makes the check FAIL with category TLS_ERROR.
- **FR-MON-008 P0:** Manual check-now is rate-limited (default 1 per monitor per 60 s, 30 per organization per hour). It uses the identical hardened worker path, is recorded with trigger MANUAL and does **not** change health counters, incidents or uptime.
- **FR-MON-009 P0:** Monitor lifecycle: DRAFT, ACTIVE, PAUSED, ARCHIVED. Health state: UNKNOWN, UP, DEGRADED, DOWN. The displayed status is PAUSED when lifecycle is PAUSED, otherwise the health state. Pausing stops new checks, incidents and notifications. Resuming resets health to UNKNOWN.
- **FR-MON-010 P1:** DNS/TCP monitors, authenticated multi-step workflows, per-region probes, redirect following with per-hop validation.
- **FR-MON-011 P0 — Retries:** `retry_attempts` 0–2 (default 1, capped by platform setting), applied only to transient network categories (DNS_TIMEOUT, CONNECT_TIMEOUT, CONNECT_ERROR, READ_TIMEOUT, TLS_HANDSHAKE_TIMEOUT), with a 1 s delay. Every attempt re-resolves and re-validates the destination. HTTP status mismatch, validation failure, TLS certificate errors and policy blocks are never retried. A check's result is that of its final attempt.
- **FR-MON-012 P0 — Check result semantics:**
  - `PASS`: response received, status expected, validation passed, elapsed ≤ latency threshold.
  - `SLOW`: as PASS but elapsed > latency threshold. Counts as available.
  - `FAIL`: the target did not meet expectations (DNS NXDOMAIN/failure, connect error/timeout, TLS error, read timeout, status mismatch, validation failed, response too large).
  - `BLOCKED`: the SSRF policy refused the destination. Not an outage. After 3 consecutive BLOCKED results the monitor is auto-paused with reason POLICY_BLOCKED, and ORG_OWNER/ORG_ADMIN are notified.
  - `INCONCLUSIVE`: probe-side fault (worker internal error, local resource exhaustion). Not attributed to the target.
  - Only scheduled PASS/SLOW/FAIL results change health counters. BLOCKED and INCONCLUSIVE neither increment nor reset them. If no conclusive scheduled result exists for 3 intervals, health becomes UNKNOWN (stale) rather than staying UP.
- **FR-MON-013 P0 — Response validation (GET only):** optional substring match or JSON-path equality on at most the first N bytes (platform cap, default 64 KiB). No regular expressions. The body is evaluated in memory and discarded.
- **FR-MON-014 P0 — Custom request headers:** up to 5 (platform cap). Header names are validated against a deny-list (Host, Content-Length, Transfer-Encoding, Connection, Upgrade, TE, Proxy-*, X-Forwarded-*, Forwarded). Names and values are encrypted together and are write-only: after save the API returns only a count and "set" markers. No request body (OD-07).
- **FR-MON-015 P0 — Limits:** monitor creation/un-archive fails with `409 LIMIT_EXCEEDED` when non-archived monitors would exceed the effective limit. The check runs under the organization row lock, so concurrent creates cannot overshoot.

### 3.5 Scheduling (normative summary; detail in Architecture §5)
- **FR-SCH-001 P0:** Workers claim due monitors with `FOR UPDATE SKIP LOCKED` only when organization is ACTIVE, monitor lifecycle is ACTIVE and domain coverage is valid. A claim sets a lease of `timeout × (retry_attempts + 1) + retry delays + 10 s` and a job ID.
- **FR-SCH-002 P0:** Fixed cadence: `next_due_at = planned_due + interval`. If more than one interval behind, the scheduler skips to the next future slot and counts missed slots (reported as coverage gaps, never as PASS).
- **FR-SCH-003 P0:** Completion is idempotent on `(monitor_id, job_id)` and discarded if the schedule generation changed (edit, pause, resume, suspension). Expired leases are reclaimable.

### 3.6 Incident management
- **FR-INC-001 P0:** `failure_threshold` default 3, `recovery_threshold` default 2. Only scheduled conclusive results (FR-MON-012) drive automatic transitions.
- **FR-INC-002 P0:** Incident types in Phase 1: OUTAGE (opened when health enters DOWN) and TLS_EXPIRY (FR-MON-007). At most one active incident per monitor per type. Sanitized evidence and an append-only event timeline are kept.
- **FR-INC-003 P0:** On recovery threshold, the active OUTAGE incident resolves automatically and outage duration is computed from detection/recovery times, labelled an estimate rather than exact customer downtime. TLS_EXPIRY resolves automatically when a check observes a certificate above the threshold.
- **FR-INC-004 P0:** Lifecycle OPEN → ACKNOWLEDGED → RESOLVED (or OPEN → RESOLVED). Members per `PERMISSION_MATRIX.md` can acknowledge, assign (to an ACTIVE member of the same organization), comment and manually resolve. Manual resolution of an OUTAGE is rejected while health is DOWN (acknowledge or pause instead), so manual action never overrides health or suppresses an ongoing failure. Resolved incidents are never reopened. A new failure opens a new incident.
- **FR-INC-005 P0:** Severity, type, status, source, opened/acknowledged/resolved times, assignee and monitor are searchable and filterable within the organization.
- **FR-INC-006 P0:** Incident transitions are transactional, replay-safe and idempotent under duplicate worker completion.
- **FR-INC-007 P1:** Manually created incidents, maintenance windows, on-call schedules and escalation, DEGRADED incidents.

### 3.7 Notifications (alerts)
- **FR-NTF-001 P0:** Organization-scoped channels: **Telegram** (organization-provided bot token, encrypted and write-only; delivery only to the fixed Telegram Bot API host) and **email** (sent through the platform SMTP relay to recipients who are ACTIVE members of the organization; OD-08). Organizations never supply SMTP hosts or arbitrary outbound URLs (ADR-014). Channels have a test action.
- **FR-NTF-002 P0:** Events: incident opened, acknowledged (optional), resolved, TLS expiry warning, monitor auto-paused by policy. Routes are configured per organization, project or monitor and per event type.
- **FR-NTF-003 P0:** Transactional outbox in the same transaction as the incident transition, retries with bounded exponential backoff (max 8 attempts), deterministic dedupe key and delivery history. Failed integrations never stall probing.
- **FR-NTF-004 P0:** Throttle repeated notifications per incident. Message bodies contain only sanitized fields: organization, project and monitor display names, display host, state, times and an incident reference. No URLs with query strings, headers or secrets.
- **FR-NTF-005 P0:** The notifier re-checks at dispatch time that the organization is ACTIVE, the channel belongs to the same organization and is enabled, and email recipients are still ACTIVE members. Otherwise the item is cancelled with a recorded reason.
- **FR-NTF-006 P1:** Slack, generic webhooks (requires the SSRF policy), external email recipients, escalation.

### 3.8 Dashboard, reports, status pages, realtime
- **FR-UI-001 P0:** Organization overview: monitor counts by status, unresolved incidents, recent checks, latency trends.
- **FR-UI-002 P0:** Monitor detail: last result, timeline, uptime %, latency p50/p95, 24h/7d/30d, configuration (fields per role), incident history.
- **FR-UI-003 P0:** Incident list/detail with sanitized evidence, acknowledge, assign, comment, resolve and timeline.
- **FR-UI-004 P0:** Public status pages are disabled by default and published explicitly. They show only chosen monitors' public display names, current status, generic public incident titles and aggregate availability, served from sanitized snapshots.
- **FR-UI-005 P0:** Private dashboard updates stream over SSE bound to one organization and membership. Membership is re-validated at connect and at least every 30 s. Clients reconnect with snapshot refresh, without a guarantee of every event.
- **FR-UI-006 P0:** Reports: uptime/latency/incident summaries per project and monitor over 24h/7d/30d, with coverage %. CSV export of aggregate figures, streamed on request after a membership check. Exports are not stored server-side and contain no URLs with query strings, headers, secrets or raw content.
- **FR-UI-007 P0:** Separate SYSTEM_ADMIN console (platform routes) and organization app with organization switcher. The SYSTEM_ADMIN console never renders organization-private data.
- **FR-UI-008 P1:** Custom branding, advanced report charts, status-page subscriptions.

### 3.9 Phase 2 compatibility (interfaces only, no feature implementation)
- **FR-EXT-001 P0:** `monitor.kind`, `measurement.source_kind`, `schema_version`, `observed_at` and `ingested_at` are explicit and extensible (Phase 1 values: kind HTTP, source_kind HTTP_PROBE).
- **FR-EXT-002 P0:** Incident evaluation consumes normalized results, not HTTPX objects.
- **FR-EXT-003 P0:** The ownership chain organization → project → monitor → measurement/incident is fixed. Future agent metrics enter as new monitor kinds and source kinds under the same chain (Architecture §11).
- **FR-EXT-004 P1:** Authenticated, organization-bound Grafana Alloy ingestion (OTLP / Prometheus remote-write) through a dedicated receiver after MVP. No agent ingestion endpoint exists in Phase 1.

## 4. Non-functional requirements
- **NFR-001 Security:** SSRF protection defends against DNS rebinding, mixed public/private answers, proxies, redirects, IPv4-mapped IPv6, encoded IP forms, URL credentials and connect-time destination change. A container egress firewall additionally denies internal networks.
- **NFR-002 Isolation:** no cross-organization access through IDs, joins, workers, notification jobs, exports, realtime events, status pages or audit views. Composite foreign keys prevent cross-organization links at the database level. The application uses a least-privilege DB role.
- **NFR-003 Performance:** target 100 monitors across 10 organizations locally at 60 s intervals, with ≥ 99% of scheduled checks starting within 10 s of due time. Not an SLA until load-tested.
- **NFR-004 Durability:** no lost incident transition between commit and dispatch (outbox). Notifications are at-least-once with deduplication.
- **NFR-005 Availability:** restart-safe leases and idempotent workers. Missing data appears as UNKNOWN, never falsely as UP.
- **NFR-006 Retention:** raw measurements 30 days, hourly rollups 12 months, incidents and audit 12 months (OD-10).
- **NFR-007 Accessibility:** keyboard-usable, clear error states, responsive 360–1440 px, WCAG 2.2 AA-oriented semantics.
- **NFR-008 Time:** UTC storage, organization/user IANA time zone for presentation, unambiguous sampling windows.
- **NFR-009 Privacy:** never persist response bodies, request headers, URL query strings outside encrypted config, resolved IP addresses or personal data from monitored endpoints.
- **NFR-010 Reproducibility:** Docker Compose dev stack, Alembic migrations applied manually, lint/type/unit/integration/E2E CI, fictional fixtures.
- **NFR-011 Secrets:** application-level authenticated encryption bound to organization and row (ADR-015). Secrets are write-only through every API, including SYSTEM_ADMIN APIs. Residual risk: infrastructure operators holding encryption keys and database access can decrypt. This is documented, not hidden.
- **NFR-012 Credentials:** no default or hardcoded credentials in code, images, compose files, fixtures or docs.

## 5. Principal journeys
1. Operator runs the bootstrap CLI → platform owner activates the SYSTEM_ADMIN account through a one-time link → SYSTEM_ADMIN creates organization "Acme (fictional)" and invites its owner.
2. Owner accepts the invitation → creates a project → verifies a domain by DNS TXT → configures a monitor → worker records PASS and health UP.
3. Three consecutive scheduled FAIL results → one OPEN OUTAGE incident → Telegram/email alert. An ORG_MEMBER acknowledges. Two consecutive successes → RESOLVED plus a recovery notice.
4. ORG_ADMIN publishes selected monitors on a status page → anonymous visitor sees only sanitized status history.
5. User with memberships in two organizations switches organization → sees only the selected organization's data. Owner of one organization removes them → that organization's API and SSE access ends while the other membership keeps working.
6. SYSTEM_ADMIN suspends an organization → its probes, notifications, member access and status page stop. Reactivation resumes them.
7. Attacker configures a URL resolving to 127.0.0.1, 169.254.169.254 or RFC 1918 space, or DNS switches target between validation and connect → probe refuses before connecting (BLOCKED).
8. SYSTEM_ADMIN opens an organization in the platform console → sees metadata and usage but no URLs, headers, channel config or incident content. Organization routes return 404 for them unless they are invited as a member.

## 6. Boundaries and decisions
- **In scope P0:** multi-tenancy, SYSTEM_ADMIN platform plane, organization roles, public HTTP/HTTPS checks, TLS expiry, incidents, Telegram/email notifications, dashboard, reports, status pages, audit.
- **Out of scope Phase 1:** agents and server CPU/RAM/disk metrics, log collection, private-network monitoring, Kubernetes, billing/payments, self-service signup, SSO/MFA for org users, complex synthetic workflows, AI root-cause claims, tracing, on-call schedules.
- Decisions with rationale: `ARCHITECTURE_DECISIONS.md`. Open decisions with defaults: `ARCHITECTURE_DECISIONS.md` §3.

## 7. Acceptance test catalog
| ID | Outcome | Gate |
|---|---|---|
| AC-001 | Organization A members cannot list, read, edit or reference organization B projects, monitors, incidents, channels or status pages (404) | G2+ |
| AC-002 | A revoked or suspended member loses API access on the next request and SSE within 30 s | G2 |
| AC-003 | An authorized public GET monitor returns PASS with measured latency | G3 |
| AC-004 | 3 failures open exactly one OUTAGE incident, even with duplicated completions | G4 |
| AC-005 | 2 successes resolve the active incident and send one recovery notification | G5 |
| AC-006 | Telegram unavailable triggers retries without affecting scheduling | G5 |
| AC-007 | A URL to a private, loopback, link-local or metadata destination is BLOCKED | G3 |
| AC-008 | DNS rebinding, mixed answers, CNAME-to-private and redirect-based SSRF cases are BLOCKED or not followed | G3 |
| AC-009 | A certificate below the threshold opens a TLS_EXPIRY incident separate from OUTAGE | G4 |
| AC-010 | Monitor pause stops new probes, incidents and notifications | G3/G4 |
| AC-011 | The public status page reveals only explicitly published sanitized fields | G5 |
| AC-012 | The scheduler lease prevents duplicate concurrent execution | G3 |
| AC-013 | 24h uptime and p95 come from consistent sampling windows with stated coverage | G6 |
| AC-014 | Browser E2E: register monitor → outage → acknowledge → recovery | G7 |
| AC-015 | One user in two organizations keeps independent roles and invitations | G2 |
| AC-016 | Probe logs, measurements, incidents and notifications contain no headers, query strings or bodies | G3–G5 |
| AC-017 | Worker restart reclaims expired leases without duplicating incident transitions | G4 |
| AC-018 | Each measurement has source kind and schema version | G3 |
| AC-019 | Bootstrap refuses when a SYSTEM_ADMIN exists. The activation token is single-use and expires. No default credentials exist | G1 |
| AC-020 | The last active SYSTEM_ADMIN cannot be deactivated. A deactivated SYSTEM_ADMIN loses platform access immediately | G1 |
| AC-021 | A SYSTEM_ADMIN without membership gets 404 on organization routes, and platform APIs never return URLs, header data, channel config or incident content | G2 |
| AC-022 | Suspension stops claims, cancels pending notifications, blocks members (403) and hides the status page. Activation resumes with health UNKNOWN | G2–G5 |
| AC-023 | The last ACTIVE ORG_OWNER cannot be removed, demoted, suspended or leave, including under concurrent requests | G2 |
| AC-024 | ORG_ADMIN cannot grant ORG_ADMIN/ORG_OWNER or modify owner/admin memberships. No user can elevate their own role. SYSTEM_ADMIN cannot issue an owner invitation to an organization that has an ACTIVE owner | G2 |
| AC-025 | Table-driven test covers every (role × action) cell of `PERMISSION_MATRIX.md` | G2+ |
| AC-026 | Org switching: no data from the previous organization is shown or fetched after switching | G2/G6 |
| AC-027 | Concurrent monitor creation cannot exceed the effective limit | G3 |
| AC-028 | Secret header values and channel credentials are never returned by any API, export, log or audit entry | G3/G5 |
| AC-029 | DB constraints reject cross-organization links (route→channel, outbox→channel, status-page→monitor, incident→assignee) | G2–G5 |
| AC-030 | BLOCKED/INCONCLUSIVE results do not change counters. 3 BLOCKED auto-pauses. Retries re-validate DNS | G3 |
| AC-031 | Check-now results do not change health, incidents or uptime | G3 |
| AC-032 | The notifier cancels items for suspended organizations, disabled channels or former members | G5 |

## 8. Open items
Open product decisions, each with the default adopted in this baseline and the gate by which it must be confirmed, are listed in `ARCHITECTURE_DECISIONS.md` §3. No feature may be claimed released until its acceptance checks pass.
