# Security and multi-tenancy summary

## Tenant isolation
- The organization comes only from the URL path (`/api/orgs/{org_id}`) and is re-validated against
  an ACTIVE membership on every request; SSE streams re-validate every 15 s.
- Non-members, including SYSTEM_ADMINs without an invitation, get `404`; suspended organizations
  `403 ORG_SUSPENDED`; missing permission `403`.
- Every route declares exactly one permission action (a test fails otherwise); the permission
  table is checked against `PERMISSION_MATRIX.md`.
- Composite organization-scoped foreign keys reject cross-tenant references in the database
  (incident→assignee, outbox→channel, route→monitor, status page→monitor, and so on).
- Workers, the notifier, reports, exports, realtime events and status pages are all
  organization-scoped and covered by isolation tests.

## SSRF and outbound traffic
- Probes: http/https on 80/443 only; no IP literals, userinfo, fragments or special-use names;
  every DNS answer must be public (including IPv4-embedded IPv6 forms); the connection is pinned to
  the validated IP; no redirects, no proxies, body cap. A verified domain never permits private or
  metadata destinations.
- The worker container installs an egress firewall that rejects private, loopback, link-local
  (metadata), CGNAT, multicast and reserved ranges, and refuses to start without it.
- The notifier container is default-deny: database, configured SMTP relay, Telegram's Bot API
  ranges and DNS only. Tenants can never configure SMTP hosts or webhook URLs.
- Validation status: both firewalls were exercised in local Docker containers (allowed database
  connection; metadata, private and arbitrary public destinations rejected; fail-closed without
  `NET_ADMIN`; uid 10001). The Telegram allowance was inspected, not exercised (that would contact
  Telegram). Cloud network policy is a deployment task.

## Secrets
- Monitor URLs, custom headers and Telegram credentials: AES-256-GCM, bound to
  organization / table / row / field, write-only through the API (headers and Telegram) and never
  logged, audited or included in notifications, exports or status pages.
- TOTP secrets use a separate key ring (`SENTINELOPS_MFA_KEYS`); recovery codes, session tokens,
  CSRF tokens, invitation and activation tokens are stored only as hashes. Passwords use Argon2id.
- Keys come from the environment; there are no default credentials anywhere.

## Authentication
- Server-side sessions in HttpOnly SameSite cookies (`__Host-` and Secure in production), CSRF
  tokens on all mutations, session rotation on login, MFA and password change, idle and absolute
  timeouts.
- Login throttling per account and per client IP (trusted-proxy aware; spoofed
  `X-Forwarded-For` from untrusted peers is ignored).
- SYSTEM_ADMIN MFA (TOTP + single-use recovery codes) is mandatory in production. Pending
  sessions can reach only the MFA endpoints; replayed codes are rejected; 5 failures revoke the
  pending session. Lost devices are recovered with `sentinelops reset-admin-mfa` (host shell,
  audited).

## Audit
Privileged, membership, monitor, incident, notification, status-page and MFA actions write an
append-only `audit_event` in the same transaction, with only non-secret fields.

## Dependency audit (G7, 1 Nov 2026)

| Scope | Tool | Result | Assessment |
|---|---|---|---|
| Python, all groups (149 packages) | pip-audit 2.9.0 | No known vulnerabilities | — |
| npm production dependencies | `npm audit --omit=dev` | 0 vulnerabilities | — |
| npm development tooling | `npm audit` | 12 moderate, all one advisory: minimatch glob amplification (GHSA-g3hv-75wg-m249) through ESLint / typescript-eslint | Development-only (never in the shipped bundle or containers). Exploitation needs attacker-controlled glob patterns at lint time, so it is not exploitable in CI or production. npm's suggested fix is a breaking downgrade; tracked until upstream releases a patched range. Medium-low priority. |

CI fails on any Python vulnerability and on high/critical npm production findings, and prints the
full npm report on every run.
