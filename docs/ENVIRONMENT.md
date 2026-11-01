# Configuration

All processes read `SENTINELOPS_*` variables (`apps/api/src/sentinelops/config.py`). Values marked
*secret* must come from an env file or secret manager, never from the repository.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `SENTINELOPS_ENV` | no | `development` | `development`, `test` or `production` (production: secure cookies, no API docs, MFA required) |
| `SENTINELOPS_DATABASE_URL` | **yes** (*secret*) | — | `postgresql+asyncpg://` URL; in production the least-privilege app login role |
| `SENTINELOPS_SECRET_KEYS` | **yes** (*secret*) | — | JSON `{"key_id": "<base64 32 bytes>"}` for organization secrets |
| `SENTINELOPS_SECRET_ACTIVE_KEY_ID` | **yes** | — | Key ID used for new ciphertext (old IDs stay for decryption) |
| `SENTINELOPS_MFA_KEYS` | production (*secret*) | `{}` | Separate key ring for SYSTEM_ADMIN TOTP secrets |
| `SENTINELOPS_MFA_ACTIVE_KEY_ID` | production | — | Active MFA key ID |
| `SENTINELOPS_ADMIN_MFA_REQUIRED` | no | production: true, otherwise false | Force or relax the SYSTEM_ADMIN MFA policy |
| `SENTINELOPS_TRUSTED_PROXIES` | behind a proxy | `[]` | JSON list of CIDRs whose `X-Forwarded-For` is trusted |
| `SENTINELOPS_PUBLIC_BASE_URL` | yes in production | `http://localhost:5173` | Browser origin used in emailed links |
| `SENTINELOPS_ALLOWED_ORIGINS` | yes in production | localhost origins | Origins allowed to send state-changing requests |
| `SENTINELOPS_COOKIE_SECURE` | no | secure unless development/test | Override cookie security |
| `SENTINELOPS_SESSION_IDLE_MINUTES` / `_ABSOLUTE_HOURS` | no | 480 / 24 | Session lifetime |
| `SENTINELOPS_SMTP_HOST` / `_PORT` / `_STARTTLS` | for email | unset / 587 / true | Platform relay (unset disables email) |
| `SENTINELOPS_SMTP_USERNAME` / `_PASSWORD` (*secret*) / `_FROM` | relay-dependent | — | Relay credentials and sender |
| `SENTINELOPS_PROBE_POLICY` | no | `strict` | `dev-fixtures` (adds loopback) is refused outside development/test |
| `SENTINELOPS_WORKER_CONCURRENCY` / `_ORG_CONCURRENCY` / `_HOST_CONCURRENCY` | no | 50 / 10 / 2 | Per-process caps (single worker is the supported topology) |
| `SENTINELOPS_WORKER_SHUTDOWN_GRACE_SECONDS` | no | 60 | Grace period for running checks on SIGTERM |
| `SENTINELOPS_LOG_LEVEL` | no | `INFO` | JSON log level |

Container-only variables:

| Variable | Container | Purpose |
|---|---|---|
| `SENTINELOPS_EGRESS_ALLOW` | worker, notifier | `host:port` list allowed through the firewall (database, SMTP relay) |
| `SENTINELOPS_EGRESS_ALLOW_CIDRS` | notifier | `cidr:port` list; defaults to Telegram's published Bot API ranges on 443 |
| `SENTINELOPS_SITE_ADDRESS` | web (Caddy) | Public hostname; Caddy obtains its TLS certificate |

Test-only: `SENTINELOPS_TEST_DATABASE_URL` (owner URL of a local `sentinelops_test`),
`SENTINELOPS_REQUIRE_INTEGRATION=1` (CI), `E2E_WEBKIT=1` (Playwright WebKit project).

Generate a key: `python3 -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"`.
