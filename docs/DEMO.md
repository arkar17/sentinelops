# Fictional demo

All data is fictional: organizations, people, `.example`/`.test` domains, measurements, incidents
and deliveries are synthetic rows. Nothing is probed and no message is sent.

## Create the demo database (separate approval required)
The seed refuses unless the database is named `*_demo` and contains no accounts.
```bash
# e.g. with the local stack: create an empty database called sentinelops_demo, point
# SENTINELOPS_DATABASE_URL at it, run the migrations, then:
sentinelops seed-demo --confirm
```
It prints the generated passwords once. Demo monitors are scheduled years ahead, so a worker
never contacts the fictional hosts.

## What it contains
- SYSTEM_ADMIN `platform-admin@sentinelops.test` (production would require MFA enrolment).
- **Northwind Traders (demo)** (Europe/Berlin): owner, admin, member, viewer; monitors
  *Storefront* (up, TLS certificate expiring in 9 days) and *Payments API* (down for 25 minutes);
  one resolved outage, one open outage, one TLS warning; email channel with sent delivery history;
  published status page `/status/northwind-status`.
- **Contoso Health (demo)** (America/New_York): owner and member; *Portal API* with a short
  resolved outage two days ago.
- 24 hours of one-minute measurements per monitor and hourly rollups.

## Walkthrough
1. Sign in as the Northwind owner: the overview shows health, open incidents, uptime with
   coverage, response-time charts and the expiring certificate; it updates live.
2. Open *Incidents* → the open outage: timeline, evidence, acknowledge, assign.
3. *Reports*: 24 h / 7 d / custom ranges, per-monitor uptime and p95, CSV export.
4. *Notifications*: channel, all-events route, delivery history (result codes only).
5. Visit `/status/northwind-status` signed out: public names and status only.
6. Sign in as the Contoso member: Northwind does not exist for them (`404` everywhere).
7. Sign in as the SYSTEM_ADMIN: platform dashboard with aggregate usage only; no monitor names,
   hosts or incident content.
