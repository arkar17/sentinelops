# Release checklist

## Gate closure (G7)
- [x] Ruff, formatting, strict Pyright, import-linter
- [x] Backend unit + integration tests with migration upgrade/downgrade/upgrade and schema match
- [x] Frontend lint, typecheck, Vitest, build
- [x] Playwright journeys (Chromium desktop + mobile in CI; WebKit locally)
- [x] Docker Compose validation (dev and production) and image builds
- [x] Dependency audit triaged ([SECURITY.md](SECURITY.md))
- [x] Backup/restore drill on disposable databases
- [x] Egress firewalls validated in local containers
- [x] Opt-in demo seed tested against the disposable database only
- [x] NFR-003 load test on a local host with simulated probes: PASS, 100% of checks started
      within 10 s, p99 ≤ 0.72 s ([performance/NFR-003_LOAD_TEST.md](performance/NFR-003_LOAD_TEST.md))

## Before any non-local deployment
- [x] PO confirmed IC-28…IC-31, 1 Nov 2026 ([ARCHITECTURE_DECISIONS.md](baseline-v1.0/ARCHITECTURE_DECISIONS.md))
- [ ] Production env file created with fresh keys; offline key backup stored
- [ ] Least-privilege app login role created; owner credentials used only for migrations
- [ ] Host/cloud firewall equivalent to the container egress rules; database not exposed
- [ ] Telegram CIDR allowlist reviewed against the provider's published ranges
- [ ] SMTP relay with SPF/DKIM for the sender domain
- [ ] HTTPS hostname and trusted-proxy CIDRs reviewed
- [ ] Bootstrap SYSTEM_ADMIN, enrol MFA, store recovery codes offline
- [ ] Scheduled, encrypted, off-host backups and a restore drill on the target host
- [ ] Load test at the NFR-003 target on production-like hardware
- [ ] Log shipping and alerting on worker/notifier heartbeats and backlogs

## Known limitations (Phase 1)
- Single worker is the supported topology; concurrency caps are per process (IC-09).
- Coverage uses each monitor's current interval (approximate after interval changes);
  latency percentiles older than 30 days are approximations from hourly rollups (IC-23).
- Notification delivery is at-least-once; a crash right after a provider accepted a message can
  repeat it (messages carry an incident link) (IC-19).
- Public status responses may be cached for up to 30 s after unpublishing (IC-21).
- Public rate limiting and the SSE hub are per API process (IC-21, IC-25).
- Expired certificates surface as TLS_ERROR failures; TLS_EXPIRY needs a prior warning-window
  observation (IC-17).
- Incident, audit and notification history are retained indefinitely in Phase 1 (IC-24).
- No member MFA, SSO, self-service signup, webhooks or agent metrics (Phase 1 scope).
- NFR-003 is load-tested only on a local development host with simulated probes; it is not an
  SLA until repeated on production-like hardware ([performance/NFR-003_LOAD_TEST.md](performance/NFR-003_LOAD_TEST.md)).
