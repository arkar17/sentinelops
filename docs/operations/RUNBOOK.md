# Operations runbook

Single-host deployment with `deploy/compose.prod.yaml`. Nothing in this repository deploys
automatically; every step below is run by an operator.

## 1. Prepare
1. Host with Docker Engine + Compose, ports 80/443 reachable, DNS `A`/`AAAA` record for the site.
2. `cp deploy/.env.production.example deploy/.env.production` (mode 600) and fill every value
   ([ENVIRONMENT.md](../ENVIRONMENT.md)). Generate fresh keys; keep a secure offline copy of
   `SENTINELOPS_SECRET_KEYS` and `SENTINELOPS_MFA_KEYS` (losing them makes encrypted data
   unreadable; they are not in database backups).
3. Review the notifier allowlist: `SENTINELOPS_EGRESS_ALLOW` gets the SMTP relay automatically;
   check `SENTINELOPS_EGRESS_ALLOW_CIDRS` against Telegram's currently published ranges.
4. Apply host/cloud firewall rules equivalent to the container rules (deployment task; not
   provided here): inbound 80/443 only; database never exposed.

## 2. Database and migrations
```bash
C="docker compose -f deploy/compose.prod.yaml --env-file deploy/.env.production"
$C up -d postgres
$C run --rm migrate                      # manual, reviewed, never automatic
# Least-privilege login role for api/worker/notifier (member of the NOLOGIN sentinelops_app role).
# Interactive, so the password never appears in shell history or process lists:
$C exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
#   CREATE ROLE sentinelops_app_login LOGIN IN ROLE sentinelops_app;
#   \password sentinelops_app_login        -- the APP_DB_PASSWORD value
```
Before every migration: take a backup (section 5), read the migration, apply, verify `/readyz`.

## 3. Start, bootstrap and MFA
```bash
$C up -d api web worker notifier
$C run --rm api sentinelops bootstrap-system-admin --email owner@yourcompany.example
```
The command prints a single-use activation link (30 minutes). After setting the password the
SYSTEM_ADMIN must enrol a TOTP authenticator (production enforces MFA) and store the 10 recovery
codes offline. Further admins are invited from the console and must also enrol.

**Lost authenticator and recovery codes:** `$C run --rm api sentinelops reset-admin-mfa --email ...`
removes MFA and revokes all sessions (audited); the admin enrols again at next login.
**All admins locked out:** `sentinelops bootstrap-system-admin --email ... --recover`.

## 4. Reverse proxy and HTTPS
Caddy (`web` service) terminates TLS with automatic certificates for `SENTINELOPS_SITE_ADDRESS`,
sets HSTS, CSP, frame and referrer headers, serves the SPA and proxies `/api`, `/healthz`,
`/readyz` (SSE unbuffered). It has the fixed address `10.89.0.2` on the `edge` network, and the
API trusts `X-Forwarded-For` only from `10.89.0.0/24` (`SENTINELOPS_TRUSTED_PROXIES`). If you put
another proxy or load balancer in front, add its address range there and nowhere else; never trust
`0.0.0.0/0`.

## 5. Backups and restore
- `deploy/backup.sh /secure/backups` — `pg_dump -Fc`, verified with `pg_restore --list`. Schedule
  it (e.g. hourly, keep 30 days) and copy backups off-host, encrypted.
- `deploy/restore.sh <dump>` restores into an **empty** database only (refuses otherwise). Create
  the `sentinelops_app` role first on a fresh server (the first migration does this on an empty
  database, or `CREATE ROLE sentinelops_app NOLOGIN`), then restore, recreate the login role and
  start the services.
- Drill (G7): a dump of a disposable `sentinelops_test` restored into a second, empty disposable
  instance with identical row counts across users, organizations, monitors, measurements,
  incidents, timeline, deliveries, audit and the schema revision. Repeat the drill after major
  upgrades.

## 6. Workers and notifier
- **Start:** both containers install their egress firewall first and refuse to start without
  `NET_ADMIN` (exit 4). They run as uid 10001 with a read-only filesystem.
- **Topology:** run one worker (per-process concurrency caps). One notifier is sufficient; several
  are safe (leases, dedupe, per-channel rate limit across notifiers).
- **Stop/upgrade:** `docker compose stop worker` sends SIGTERM: no new claims, running checks get
  60 s, unfinished leases expire and are reclaimed. Results that arrive late are discarded by
  job/generation checks, so restarts never duplicate incidents. The notifier finishes its batch;
  unfinished deliveries are retried after their lease expires (at-least-once).
- **Health:** worker/notifier heartbeats, claim lag, backlogs and failed deliveries appear on the
  platform dashboard. The API has `/healthz` (liveness) and `/readyz` (database).

## 7. Incidents of the platform itself
| Symptom | Check |
|---|---|
| Claim lag growing | Worker running? Heartbeat on the dashboard? Database CPU? |
| Outbox backlog / failures | Notifier heartbeat; delivery result codes (`TELEGRAM_*`, `MAIL_*`); egress allowlist |
| Users see 403 `ORG_SUSPENDED` | Organization suspended in the console (by design) |
| Admin cannot log in | Throttle lockout (15 min), MFA device: use recovery code or `reset-admin-mfa` |
