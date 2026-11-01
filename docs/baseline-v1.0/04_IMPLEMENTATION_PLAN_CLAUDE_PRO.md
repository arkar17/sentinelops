# SentinelOps — Implementation and QA Plan · Baseline v1.0 · 31 Oct 2026

Requirements: `01_SRS.md`. Authorization: `PERMISSION_MATRIX.md`. Decisions and open decisions: `ARCHITECTURE_DECISIONS.md`. Precedence: `README_DOCUMENTS.md`.

## 1. Delivery approach
Build with **Claude Code Pro locally on the Mac**, in small, bounded tasks, on one Git branch per gate. Claude Pro subscription usage and Claude Code cloud credits are separate allowances; do not assume the cloud credit balance controls local usage. Do not start a large autonomous all-at-once implementation. After each gate, report the exact tests/commands run, changes, remaining failures and commit SHA. The Product Owner explicitly approves migrations, seeds, paid resources and deployment.

**Ordering principle:** identity, the SYSTEM_ADMIN platform plane and organization management with isolation tests are complete **before** any monitoring functionality (G3+). Every later gate reuses the G2 isolation and permission test harness.

## 2. Milestones
| Gate | Deliverable | Minimum exit criteria | Open decisions to close before start | Relative effort |
|---|---|---|---|---|
| G0 | Repository skeleton and engineering policy | README, CLAUDE.md, lint/typecheck/pytest/TS checks, Docker Compose dev config (no secrets), CI skeleton | — | Small |
| G1 | Identity and SYSTEM_ADMIN platform plane | Sessions, CSRF, Argon2id, activation/reset tokens, bootstrap CLI, platform admin invite/deactivate, platform settings, platform audit, minimal admin console | OD-01 | Medium |
| G2 | Organizations, membership and tenant isolation | SYSTEM_ADMIN org create/suspend/activate/limits, owner invitation, roles/status, role-assignment rules, last-owner invariant, org switching, projects, org audit, permission-matrix enforcement, isolation harness | OD-02, OD-03, OD-04, OD-09, OD-13 | Medium–High |
| G3 | Safe monitor/probe engine | Domain verification, SSRF policy and pinned-IP transport, monitor CRUD with limits, encrypted headers, worker claim/lease/complete, retries, result semantics, TLS capture, check-now | OD-05, OD-06, OD-07, OD-15 | High |
| G4 | Incident engine | Health state machine, OUTAGE and TLS_EXPIRY incidents, dedupe, ack/assign/comment/resolve rules, timeline, staleness | — | Medium |
| G5 | Notifications and status pages | Telegram and platform-SMTP email channels, routes, outbox/retries/dedupe, dispatch-time re-validation, opt-in public status pages with snapshots | OD-08 | Medium |
| G6 | Dashboards, reports, platform usage | Org overview, monitor/incident views, uptime/p95 with coverage, CSV export, SSE, completed SYSTEM_ADMIN dashboard, responsive UI | OD-10 | Medium |
| G7 | QA and release preparation | Two-org journeys in Playwright (incl. admin console and org switching), load target, security review, backup/restore, runbook, fictional demo seed script (not run without approval) | OD-11, OD-01 (deployment) | Medium |

**Gate rule:** a gate may not start until the previous gate's exit criteria pass and the open decisions listed for it are confirmed or explicitly accepted at their default by the Product Owner.

**Freeze:** no extra features until all P0 acceptance tests pass. Phase 2 (Grafana Alloy) is a separately approved project after the MVP demonstration. No agent receiver, endpoint or credential is built in Phase 1.

## 3. Gate details and test strategy
### G0 — Skeleton
Set up the Python FastAPI package with `api`, `worker`, `notifier` and `cli` entrypoints (stubs), the React + TypeScript (Vite) app, PostgreSQL in Compose, Alembic configured with manual-only application, pytest, Ruff, type checker, and an import-linter rule forbidding `platform → secrets` imports. Create a root CLAUDE.md that records document precedence, scope, data safety and "no default credentials". `.env.example` contains placeholders only. No production connections, no DNS/network probing, no user creation.

### G1 — Identity and SYSTEM_ADMIN
Implement `app_user`, `session`, `auth_token`, `platform_admin`, `platform_admin_invitation`, `platform_settings` and `audit_event` (migration `0001`, drafted and shown; applied only to a disposable test DB with approval). Login/logout, CSRF, throttling, session rotation, password reset, platform mail through the dev mail-catcher.
- **Bootstrap CLI:** refuses if an ACTIVE SYSTEM_ADMIN exists; creates a passwordless PENDING_ACTIVATION user; prints a one-time 30-minute activation link; `--recover` path; audited.
- **Platform admins:** invite, accept, deactivate, last-admin protection, no self-deactivation.
- Minimal admin console: login, activation, platform admins, settings.
- Tests: AC-019, AC-020; no default credentials anywhere (repository grep test for password-like literals in compose/fixtures); token single-use and expiry; session revocation on reset; platform routes deny non-admins.

### G2 — Organizations and isolation
Implement `organization`, `organization_limit`, `organization_member`, `org_invitation`, `user_preference` and `project` (migration `0002`).
- SYSTEM_ADMIN: create organization with owner invitation, rename, limits, suspend/activate (with generation and outbox hooks stubbed for later gates), metadata-only views.
- Organization plane: authorization pipeline (§8 of the architecture), `authz` table generated from `PERMISSION_MATRIX.md`, invitations, role/status changes, removal, leave, last-owner invariant under the organization row lock, ORG_ADMIN assignment limits, org switching endpoints, projects CRUD, org audit view including platform actions.
- UI: organization switcher, members page, projects page; cache keyed by org and cleared on switch.
- **Isolation harness (reused by all later gates):** fixtures for two organizations, a user in both with different roles, a SYSTEM_ADMIN without membership. Every org route is called with foreign IDs and foreign org paths (expect 404), and the role×action matrix runs as a table-driven test.
- Tests: AC-001 (projects), AC-002, AC-015, AC-021, AC-022 (API part), AC-023 including concurrent demotion race, AC-024, AC-025, AC-026 (API), AC-029 (project FKs).

### G3 — Safe probe engine (security-first)
Build the URL parser, IP classifier and domain verification first, and pass the full SSRF negative matrix before any real HTTPX network call is permitted. Implement the pinned-IP transport with intact Host/SNI and certificate verification. **If a safe transport cannot be demonstrated, stop and report.** Then: monitor CRUD with limits under the organization lock, encrypted headers (write-only), domain exception requests and SYSTEM_ADMIN decisions, `monitor_schedule`/`monitor_health`/`measurement` (migrations `0003`, `0004`), worker claim/lease/complete with generation checks, bounded concurrency, retries, result semantics, TLS expiry capture, check-now, BLOCKED auto-pause, suspension join in the claim query. Tests use a fake transport and a fake clock. No production external probes in tests.
- Tests: AC-003 (fake transport), AC-007, AC-008, AC-010 (probe part), AC-012, AC-016 (probe/logs), AC-018, AC-027, AC-028 (headers), AC-030, AC-031, AC-022 (claims stop).

### G4 — Incident engine
State machine as pure functions plus transactional orchestration, OUTAGE and TLS_EXPIRY incidents, partial unique active index, ack/assign/comment/resolve with the DOWN-resolve rule, assignee composite FK, staleness task, audit (migration `0005_incidents`). Run 100 concurrent duplicate completions and expect one incident and one outbox row per transition.
- Tests: AC-004, AC-009, AC-010 (incident part), AC-017, AC-029 (assignee).

### G5 — Notifications and status pages
Telegram (fixed host) and platform-SMTP email channels with member recipients, encrypted credentials, routes, outbox lease/retry/backoff/dedupe, dispatch-time re-validation, delivery history. Opt-in status pages with snapshot builder and public endpoint (migrations `0006_notifications`, `0007_status_pages`; IC-13, IC-22). All external delivery is mocked in tests; no real contacts.
- Tests: AC-005, AC-006, AC-011, AC-016 (notifications), AC-022 (outbox cancel, status page 404), AC-028 (tokens), AC-029 (route/outbox/recipient/status-page FKs), AC-032.

### G6 — Dashboards, reports, platform usage
Rollups, retention jobs, organization dashboard, monitor and incident views, reports with the denominator/coverage policy and a stable percentile method, streamed CSV export, SSE with membership re-validation, completed SYSTEM_ADMIN dashboard from platform views. No sensitive data on status pages or in the admin console.
- Tests: AC-013, AC-026 (UI), AC-002 (SSE), admin-console metadata-only assertion (AC-021 UI), mobile usability.

### G7 — QA and release preparation
Playwright end-to-end: bootstrap → org creation → owner onboarding → monitor → outage → acknowledge → recovery; tenant isolation; org switching; suspension. Fake domains and simulated probes. Load test at the NFR-003 target. Security review (SSRF, authz, secrets, admin plane). Backup and restore against a disposable DB. Runbook. A fictional demo seed script, run only with manual approval against a `_demo` DB. Never deploy silently.
- Tests: AC-014 and full P0 acceptance matrix.

## 4. Execution rules
- Run unit tests before DB integration tests; targeted suites during development, the full suite at gate closure.
- Database migrations: generate and show SQL, print the target, confirm disposable naming and emptiness, and request approval before the first apply. No destructive operations.
- Never create users, organizations or credentials through migrations or seeds. The only path to the first SYSTEM_ADMIN is the bootstrap CLI, run by the operator.
- No paid services, external notifications to real contacts, DNS changes, webhook registrations or production deployment without approval.
- No secrets in the repository, logs, screenshots, fixture files or issue reports.
- Commit only verified changes on the gate's topic branch. Do not auto-merge or auto-open PRs.
- One agent. Avoid repeated full SRS reads; follow section-specific traceability (FR/AC IDs, permission action IDs).
- For bugs, add a reproducer first. Do not weaken tests to make CI green.
- Never claim browser tests passed when only unit tests ran.
- If documents conflict, stop and report per `README_DOCUMENTS.md`; do not silently pick one.

## 5. Quality gates
- **G1:** bootstrap refuses a second run; 0 default credentials; last-admin invariant holds; non-admins get 0 platform access.
- **G2:** 0 unauthorized cross-org accesses across all org routes; 100% role×action cells tested; last-owner invariant holds under concurrent requests; SYSTEM_ADMIN without membership sees 0 org-private fields.
- **G3:** 0 successful forbidden egress in the SSRF matrix; 100 concurrent claims yield no duplicate active lease; timeouts and failures correctly categorized; limits never exceeded under concurrency.
- **G4:** exactly one open incident and one outbox event under concurrent duplicate results; deterministic recovery.
- **G5:** notification outages do not affect probe throughput; 0 credential leakage; 0 cross-org deliveries.
- **G6:** correct uptime denominators and coverage on controlled fixtures; mobile usability; admin console metadata-only.
- **G7:** all P0 acceptance IDs covered, CI green, demo readable, release blockers documented.

## 6. Recommended Claude Code kickoff prompt
```
We are building SentinelOps — a multi-tenant, Python-first, agentless API monitoring and incident SaaS.
Read docs/baseline-v1.0/README_DOCUMENTS.md first, then only the sections you need from
docs/baseline-v1.0/01_SRS.md, 02_TECHNICAL_ARCHITECTURE.md, 03_DATABASE_DESIGN.md,
04_IMPLEMENTATION_PLAN_CLAUDE_PRO.md, PERMISSION_MATRIX.md and ARCHITECTURE_DECISIONS.md.
For this task, implement ONLY Gate G0: repository skeleton, root CLAUDE.md, Python FastAPI package
(api/worker/notifier/cli stubs) and React + TypeScript (Vite) workspace, Ruff, pytest, type checks,
import-linter rule (platform must not import secrets), Docker Compose dev infrastructure,
.env.example with placeholders only, and minimal CI.
Do not implement auth, organizations, monitoring probes, incidents or Phase 2 agents.
Do not create or apply migrations, seeds, users or test data without approval. No default credentials.
Do not provision services, spend money or deploy.
Use one agent, small dependencies, and a concise end report: files changed, commands/tests, commit SHA,
blockers, exact next gate.
```

## 7. Decisions before G0
All decisions needed for G0 are made. Open decisions and the gate each one blocks are listed in `ARCHITECTURE_DECISIONS.md` §3.

## 8. MVP handover checklist
- [ ] Each G0–G7 closure documented
- [ ] Full acceptance matrix passing
- [ ] Permission matrix fully covered by tests
- [ ] SYSTEM_ADMIN bootstrap and recovery runbook verified on a disposable environment
- [ ] Privacy, SSRF and admin-plane review approved
- [ ] Fictional two-org demo prepared without production data
- [ ] DB backup/restore demonstrated
- [ ] Scheduler/worker restart and retry safety verified
- [ ] Docker runbook and troubleshooting published
- [ ] Screenshots and architecture diagram for portfolio
- [ ] Outstanding P1 / Phase 2 backlog recorded
