# SentinelOps — Engineering Guide for Claude Code

Multi-tenant, agentless API monitoring and incident management SaaS. Python/FastAPI modular monolith, PostgreSQL, React + TypeScript.

## Source of truth
- Planning baseline: `docs/baseline-v1.0/`. Start with `README_DOCUMENTS.md` (document set, **precedence**, change control).
- Precedence: `01_SRS.md` > `PERMISSION_MATRIX.md` > `ARCHITECTURE_DECISIONS.md` > `02_TECHNICAL_ARCHITECTURE.md` > `03_DATABASE_DESIGN.md` > `04_IMPLEMENTATION_PLAN_CLAUDE_PRO.md`.
- If documents conflict, **stop and report** both passages. Do not silently pick one. Never relax a security control based on a lower-precedence document.
- Read only the sections needed for the current task, and trace work to FR/AC/ADR/permission IDs.

## Current status
- **G0–G7 complete** (foundation; identity + SYSTEM_ADMIN plane; organizations and tenant isolation; domain verification, SSRF-safe probe engine, worker scheduling, measurements; health state machine, incidents and timeline; Telegram/email notifications via transactional outbox and notifier; opt-in public status pages from sanitized snapshots; dashboards, reports with coverage, CSV export, hourly rollups and retention, SSE live updates, platform usage dashboard; SYSTEM_ADMIN TOTP MFA, trusted proxies, notifier egress firewall, Playwright E2E, production compose, backup/restore, demo seed). The MVP is release-prepared but not deployed; any deployment or merge to main needs explicit approval.
- Supported MVP topology: a single worker process (per-org/per-host caps are per process, IC-09).
- Work one gate at a time on a topic branch. Do not implement features from later gates.

## Layout
```
apps/api/                  Python package `sentinelops` (uv, Python 3.14)
  src/sentinelops/
    api/                   FastAPI app factory, health endpoints, request-ID middleware
    worker/ notifier/      process entrypoints: probe worker (G3), notification dispatcher (G5)
    cli/                   operator CLI: bootstrap-system-admin [--recover], reset-admin-mfa, seed-demo
    config.py              SENTINELOPS_* settings (no credential defaults)
    errors.py              structured error envelope {"error": {code, message, request_id, details}}
    log_config.py          JSON logging
    clock.py               clock.now(): the only time source (tests freeze it)
    mail.py                platform SMTP mailer (dev: mailpit)
    db/                    SQLAlchemy 2 Base, engine, request session, model registry
    identity/              users, sessions, CSRF, throttling, activation/reset tokens (G1); admin MFA (G7)
    platform/              SYSTEM_ADMIN plane: bootstrap, admins, settings, audit view (G1)
    audit/                 append-only audit writer (G1)
    tenancy/               organizations, memberships, invitations, OrgPermission context (G2)
    authz/                 ORG_PERMISSIONS table; tests compare it with PERMISSION_MATRIX.md
    catalog/               projects, domains (DNS TXT), monitors, eligibility (G2-G3)
    secrets/               AES-GCM SecretBox bound to org/table/row/field (never import from platform)
    probe_policy/          URL and destination-IP policy (code, not settings)
    probes/http/           pinned-IP HTTPX transport + check engine (results only, no secrets)
    scheduler/             claim/complete with leases, runner, worker loop (G3)
    measurements/          append-only results; rollups + retention, reports, dashboard, CSV export (G6)
    incidents/             pure health/incident state machine, engine (runs inside completion),
                           member operations, timeline events (events.emit enqueues notifications)
    notifications/         channels (Telegram org bot token, write-only; email to ACTIVE members via
                           platform relay), routes, outbox (secret-free), dispatcher, Telegram client
    status_pages/          page management, allowlisted snapshot builder, public /api/status/{slug}
    realtime/              SSE /api/orgs/{org}/events via pg_notify + one LISTEN connection per API process
                           module boundaries from architecture §4 (empty until their gate)
  migrations/              Alembic (async env); 0001 identity/platform, 0002 organizations, 0003 catalog, 0004 measurements, 0005 incidents, 0006 notifications, 0007 status pages, 0008 platform views + retention grants, 0009 admin MFA
  tests/                   unit tests; tests/integration/ needs the disposable DB
apps/web/                  React + TypeScript + Vite, ESLint, Vitest
compose.yaml               postgres, api, web; manual `migrate`; `workers` profile
docs/baseline-v1.0/        approved planning baseline
docs/                      README-level docs: ARCHITECTURE, SECURITY, ENVIRONMENT, DEMO, RELEASE_CHECKLIST, operations/RUNBOOK
deploy/                    production compose (Caddy edge), backup/restore scripts, env example
```
Mapping of product areas to modules: organizations → `tenancy`; platform administration → `platform`; monitoring → `catalog`, `probe_policy`, `probes`, `scheduler`, `measurements`; incidents → `incidents`; alerts → `notifications`; status pages → `status_pages`; reports → `measurements` read models (FR-UI-006); authorization → `authz`.

## Commands
```bash
# Backend (apps/api)
uv sync
uv run ruff check . && uv run ruff format --check .
uv run pyright
uv run lint-imports          # architecture boundaries (platform must not import secrets)
uv run pytest                # integration tests skip unless the variable below is set

# Integration tests: a disposable local DB named exactly sentinelops_test (guarded)
SENTINELOPS_TEST_DATABASE_URL=postgresql+asyncpg://postgres:<pw>@127.0.0.1:<port>/sentinelops_test uv run pytest

# Frontend (apps/web)
npm ci
npm run lint && npm run typecheck && npm test && npm run build

# Browser E2E (apps/web): fake DNS/probes/mail/Telegram, guarded sentinelops_test only
SENTINELOPS_TEST_DATABASE_URL=... npm run e2e          # E2E_WEBKIT=1 adds WebKit

# Local stack (repo root): copy .env.example to .env and set POSTGRES_PASSWORD first
docker compose up --build    # postgres, api (http://127.0.0.1:8000), web (http://127.0.0.1:5173)
```

## Non-negotiable rules
- **No default or hardcoded credentials** anywhere: code, compose, fixtures, docs. The first SYSTEM_ADMIN is created only by `sentinelops bootstrap-system-admin`, run by the operator. Never run it against a real database without explicit approval.
- Integration tests may only touch a local database named exactly `sentinelops_test`; `tests/support/disposable_db.py` enforces this and the migration scope before migrating. Do not weaken that guard.
- Security-sensitive account changes run in one transaction and write an `audit_event`. Never put tokens, hashes or passwords in audit details, logs or responses.
- **Never** create, apply or downgrade migrations, run seeds, or perform destructive DB operations without explicit approval. `docker compose run --rm migrate` is manual-only. Disposable `_test`/`_demo` databases only.
- No paid services, deployments, DNS changes, external notifications or real client data. Notification tests use fake Telegram clients and mailers (`tests/integration/g5.py`); never real tokens, chats or recipients. Probes go only through `probes/http/engine.run_check` (pinned validated IP, no redirects, no proxies). Tests use fake resolvers/backends (`tests/probe/fakes.py`) or loopback TLS under the dev-fixtures policy; never real third-party hosts. The worker container must keep its egress firewall entrypoint.
- Every tenant query is scoped by `organization_id` from the validated path context. Cross-org access returns 404 (FR-ID-003).
- Every `/api/orgs/{org_id}` route takes `Depends(OrgPermission("<action>"))`; every `/api/admin` route takes `Depends(PlatformPermission("<action>"))`. A test fails if a route declares none or more than one. New tenant tables follow the composite-FK pattern (`UNIQUE(organization_id, id)` on parents, `(organization_id, parent_id)` FKs on children); membership/limit changes lock the organization row first.
- `sentinelops.platform` must never import `sentinelops.secrets` (ADR-005, enforced by import-linter).
- Never log or return secrets, header values, URL query strings, response bodies or DB connection details. Validation errors never echo input.
- Tests must not need network access or a running database unless explicitly marked as integration tests against an approved disposable DB.
- Add a reproducer before fixing a bug. Never weaken tests to make CI green. Never claim tests passed that were not run.
- Commit only verified changes on the gate's branch. No auto-merge, no PRs unless asked.
