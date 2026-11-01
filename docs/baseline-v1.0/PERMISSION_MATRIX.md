# SentinelOps — Permission Matrix · Baseline v1.0 · 31 Oct 2026

This document is normative for authorization. Every API route declares exactly one action ID from this file, and a table-driven test (AC-025) covers every cell. `02_TECHNICAL_ARCHITECTURE.md` §8 defines how it is enforced.

**Legend:** ✅ allowed · ❌ denied (403 for an ACTIVE member; 404 for a non-member) · ◐ allowed with the stated restriction.

## 1. Planes and evaluation rules
1. **Two planes.** Platform actions (`PLT.*`) require an ACTIVE `platform_admin` row. Organization actions (`ORG.*` and below) require an ACTIVE `organization_member` row for the organization in the request path. Neither plane implies the other. A SYSTEM_ADMIN who is also a member of an organization acts there only with that membership role.
2. **Non-membership is invisible.** A non-member, a REMOVED/SUSPENDED member or a SYSTEM_ADMIN without membership gets `404` on every organization route. A cross-organization entity ID also gets `404`.
3. **Suspended organization.** Every organization route returns `403 ORG_SUSPENDED` to members while the organization is SUSPENDED, except `SELF.list_orgs`, which shows the state.
4. **Secrets are write-only for everyone.** No role in either plane can read back custom header values, Telegram tokens or any ciphertext through any API. The decrypted full monitor URL is returned only to `MON.update` holders, in the edit form (§5). "View" below never includes secret values.
5. **Default deny.** An action not listed here is denied until this matrix is amended.

## 2. Platform plane (SYSTEM_ADMIN)
| Action ID | Capability | SYSTEM_ADMIN | Any non-admin user |
|---|---|---|---|
| PLT.dashboard.view | Platform dashboard: aggregate usage, worker/outbox health | ✅ | ❌ |
| PLT.org.list / PLT.org.view | Organization metadata (FR-PLT-006 allowlist only) | ✅ | ❌ |
| PLT.org.create | Create organization and invite initial ORG_OWNER | ✅ | ❌ |
| PLT.org.update | Rename organization, change slug/timezone | ✅ | ❌ |
| PLT.org.suspend / PLT.org.activate | Change organization state | ✅ | ❌ |
| PLT.org.limits | Set per-organization limit overrides | ✅ | ❌ |
| PLT.org.owner_invite | Issue an ORG_OWNER invitation (initial owner, or recovery of an ownerless organization); audited and shown in the org audit log | ◐ only while the organization has **no** ACTIVE ORG_OWNER | ❌ |
| PLT.org.delete | Hard delete organization | ❌ (Phase 1, OD-11) | ❌ |
| PLT.admin.list / PLT.admin.invite | View and invite platform admins | ✅ | ❌ |
| PLT.admin.deactivate | Deactivate another SYSTEM_ADMIN | ◐ not self; never the last ACTIVE one | ❌ |
| PLT.settings.view / PLT.settings.update | Platform limits and operational settings (cannot relax SSRF policy) | ✅ | ❌ |
| PLT.domain_exception.decide | Approve/reject domain-verification exception requests | ✅ | ❌ |
| PLT.audit.view | Platform audit log | ✅ | ❌ |
| PLT.user.disable | Disable a global user account | ❌ (Phase 1, OD-13) | ❌ |
| PLT.impersonate | Act as another user | ❌ (never) | ❌ |
| PLT.org_data.view | Monitor URLs, headers, validation rules, channel config, incident content, member lists | ❌ (OD-12) | ❌ |
| PLT.secret.decrypt | Any decryption of organization secrets | ❌ (never) | ❌ |

## 3. Organization plane
| Action ID | Capability | ORG_OWNER | ORG_ADMIN | ORG_MEMBER | VIEWER |
|---|---|---|---|---|---|
| **Organization** | | | | | |
| ORG.view | View organization profile, own role, usage vs limits | ✅ | ✅ | ✅ | ✅ |
| ORG.update | Edit name, timezone | ✅ | ❌ | ❌ | ❌ |
| ORG.audit.view | Organization audit log (incl. platform actions on this org) | ✅ | ✅ | ❌ | ❌ |
| ORG.state.change | Suspend/activate organization | ❌ (SYSTEM_ADMIN only) | ❌ | ❌ | ❌ |
| ORG.delete | Delete organization | ❌ (Phase 1) | ❌ | ❌ | ❌ |
| **Members** | | | | | |
| MEM.list | List members, roles, statuses | ✅ | ✅ | ✅ | ✅ |
| MEM.invite | Invite member | ✅ any role | ◐ ORG_MEMBER/VIEWER only | ❌ | ❌ |
| MEM.invitation.revoke | Revoke pending invitation | ✅ | ◐ for ORG_MEMBER/VIEWER invitations | ❌ | ❌ |
| MEM.role.change | Change another member's role | ✅ (last-owner rule) | ◐ between ORG_MEMBER and VIEWER only, on ORG_MEMBER/VIEWER targets | ❌ | ❌ |
| MEM.status.change | Suspend/reactivate a membership | ✅ (last-owner rule) | ◐ ORG_MEMBER/VIEWER targets | ❌ | ❌ |
| MEM.remove | Remove a member | ✅ (last-owner rule) | ◐ ORG_MEMBER/VIEWER targets | ❌ | ❌ |
| MEM.leave | Leave the organization | ◐ not the last ACTIVE owner | ✅ | ✅ | ✅ |
| **Projects** | | | | | |
| PRJ.view | View projects | ✅ | ✅ | ✅ | ✅ |
| PRJ.create / PRJ.update / PRJ.archive | Manage projects | ✅ | ✅ | ❌ | ❌ |
| **Domains** | | | | | |
| DOM.view | View domains and verification status | ✅ | ✅ | ✅ | ❌ |
| DOM.manage | Add domain, run verification, request admin exception | ✅ | ✅ | ❌ | ❌ |
| **Monitors** | | | | | |
| MON.view | View monitor status, history, display name, display host | ✅ | ✅ | ✅ | ✅ |
| MON.view_config | View configuration incl. `display_url`, method, thresholds, response validation rule and custom header **count** (never names or values) | ✅ | ✅ | ✅ | ❌ |
| MON.create / MON.update | Create/edit monitors (non-secret fields, URL) | ✅ | ✅ | ❌ (OD-04) | ❌ |
| MON.secret.write | Set/replace/clear custom request headers | ✅ | ✅ | ❌ | ❌ |
| MON.secret.read | Read back custom header values | ❌ | ❌ | ❌ | ❌ |
| MON.pause / MON.resume | Pause/resume monitoring | ✅ | ✅ | ❌ | ❌ |
| MON.archive | Archive/un-archive (limit-checked) | ✅ | ✅ | ❌ | ❌ |
| MON.check_now | Manual check (rate-limited) | ✅ | ✅ | ✅ | ❌ |
| **Incidents** | | | | | |
| INC.view | View incidents, sanitized evidence, timeline | ✅ | ✅ | ✅ | ✅ |
| INC.acknowledge | Acknowledge | ✅ | ✅ | ✅ | ❌ |
| INC.assign | Assign to an ACTIVE member of this organization | ✅ | ✅ | ✅ | ❌ |
| INC.comment | Add timeline comment | ✅ | ✅ | ✅ | ❌ |
| INC.resolve | Manual resolve (rejected for OUTAGE while health is DOWN) | ✅ | ✅ | ✅ | ❌ |
| **Alerts (notifications)** | | | | | |
| NTF.view | View channels (type, label, enabled, recipients) and routes | ✅ | ✅ | ✅ | ❌ |
| NTF.channel.manage | Create/edit/disable channels, set credentials (write-only), manage recipients | ✅ | ✅ | ❌ | ❌ |
| NTF.channel.test | Send test notification | ✅ | ✅ | ❌ | ❌ |
| NTF.route.manage | Manage routes | ✅ | ✅ | ❌ | ❌ |
| NTF.delivery.view | View delivery history (result codes only) | ✅ | ✅ | ✅ | ❌ |
| **Dashboard and reports** | | | | | |
| RPT.dashboard | Organization dashboard and realtime stream (SSE) | ✅ | ✅ | ✅ | ✅ |
| RPT.view | Uptime/latency/incident reports | ✅ | ✅ | ✅ | ✅ |
| RPT.export | CSV export of aggregates | ✅ | ✅ | ✅ | ❌ |
| **Status pages** | | | | | |
| STP.view | View status page configuration and private preview | ✅ | ✅ | ✅ | ✅ |
| STP.manage | Create/edit pages, select monitors, set public names | ✅ | ✅ | ❌ | ❌ |
| STP.publish | Enable/disable public access | ✅ | ✅ | ❌ | ❌ |
| **Self (any authenticated user)** | | | | | |
| SELF.list_orgs / SELF.switch_org | List own ACTIVE memberships; set UI preference | ✅ | ✅ | ✅ | ✅ |
| SELF.profile | Change own password, timezone; view own sessions; log out other sessions | ✅ | ✅ | ✅ | ✅ |
| **Public (anonymous)** | | | | | |
| PUB.status_page | Read published snapshot by slug | anyone | anyone | anyone | anyone |

## 4. Role assignment rules (normative)
1. ORG_OWNER may assign any organization role and change any membership, subject to rule 4.
2. ORG_ADMIN may act only on memberships or invitations whose current **and** resulting roles are ORG_MEMBER or VIEWER.
3. Nobody can change their own role or status, except an ORG_OWNER demoting themself or leaving while at least one other ACTIVE ORG_OWNER exists.
4. **Last-owner invariant:** after any change, the organization keeps at least one ACTIVE ORG_OWNER. This is checked under the organization row lock and covers remove, suspend, demote and leave. An organization created by a SYSTEM_ADMIN has zero owners only until the first owner invitation is accepted. In that window only `PLT.org.owner_invite` can add owners.
5. Removing or suspending a membership unassigns its incidents, removes it from email recipients and closes its SSE streams within 30 s.
6. **Last-SYSTEM_ADMIN invariant:** at least one ACTIVE `platform_admin` must remain. No SYSTEM_ADMIN may deactivate themself.

## 5. Field visibility summary
| Field | SYSTEM_ADMIN (platform) | ORG_OWNER / ORG_ADMIN | ORG_MEMBER | VIEWER | Public |
|---|---|---|---|---|---|
| Organization name, slug, state, counts | ✅ | ✅ | ✅ | ✅ | ❌ |
| Owner contact emails | ✅ | ✅ | ✅ | ✅ | ❌ |
| Member list | ❌ | ✅ | ✅ | ✅ | ❌ |
| Verified domain FQDNs | ✅ | ✅ | ✅ | ❌ | ❌ |
| Monitor display name, host, status | ❌ (counts only) | ✅ | ✅ | ✅ | ◐ published public name and status only |
| Monitor `display_url`, method, thresholds, validation rule | ❌ | ✅ | ✅ | ❌ | ❌ |
| Full URL incl. query (decrypted) | ❌ | ◐ shown in edit form only | ❌ | ❌ | ❌ |
| Header values, channel tokens | ❌ | ❌ (write-only) | ❌ | ❌ | ❌ |
| Incident titles, evidence, comments | ❌ (counts only) | ✅ | ✅ | ✅ | ◐ generic public title only |
| Audit log | ✅ platform scope | ✅ org scope (owners and admins) | ❌ | ❌ | ❌ |

The full URL may contain a sensitive query string, which is why it is encrypted at rest and visible only in the edit form to users holding `MON.update`.
