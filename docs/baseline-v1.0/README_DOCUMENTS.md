# SentinelOps — Documentation Set · Baseline v1.0 · 31 Oct 2026

## 1. Status
**Baseline v1.0.** The documents below were reviewed together for consistency on 31 Oct 2026 and incorporate the Product Owner decision brief of the same date. Where the brief was silent, a default was chosen, implemented consistently across the set, and listed as an open decision (OD-01…OD-15) in `ARCHITECTURE_DECISIONS.md` §3. On 31 Oct 2026, with the approval of Gate G0, the Product Owner closed all open decisions with their defaults accepted (closure record in `ARCHITECTURE_DECISIONS.md` §3). The MVP scope is unchanged.

## 2. Documents
| File | Purpose | Normative for |
|---|---|---|
| `README_DOCUMENTS.md` | This index: status, precedence, change control | Document governance |
| `01_SRS.md` | Software Requirements Specification: roles, FR/NFR, journeys, acceptance tests | **What** the system must do |
| `PERMISSION_MATRIX.md` | Platform and organization authorization, role-assignment rules, field visibility | **Who** may do what |
| `ARCHITECTURE_DECISIONS.md` | ADRs, open decisions register, draft contradiction log | **Why**, and what is still open |
| `02_TECHNICAL_ARCHITECTURE.md` | Modules, scheduling, SSRF, auth pipeline, APIs, Phase 2 boundary | **How** it is built |
| `03_DATABASE_DESIGN.md` | Tables, constraints, isolation review, migration plan | **How data** is stored and isolated |
| `04_IMPLEMENTATION_PLAN_CLAUDE_PRO.md` | Gates G0–G7, test strategy, execution rules, kickoff prompt | **In what order** it is built |

## 3. Precedence
If two documents conflict:
1. `01_SRS.md`
2. `PERMISSION_MATRIX.md` (wins over the SRS **only** on the exact action/role cells it defines; the SRS role summaries are descriptive)
3. `ARCHITECTURE_DECISIONS.md`
4. `02_TECHNICAL_ARCHITECTURE.md`
5. `03_DATABASE_DESIGN.md`
6. `04_IMPLEMENTATION_PLAN_CLAUDE_PRO.md`

A conflict is a **defect**. The implementer stops, reports both passages, and continues only after the documents are corrected. Precedence decides which reading is safe to assume while the fix is pending; it does not mean the conflict can be ignored. Security controls are never relaxed on the basis of a lower-precedence document.

## 4. Change control
- Edits that change behavior, data shape, permissions or scope require: (a) an ADR (new, or one that supersedes an existing ADR), (b) consistent updates to every affected document, and (c) a version bump (v1.1 for compatible changes, v2.0 for scope changes) recorded in §6.
- Closing an open decision at its default requires only marking it closed in `ARCHITECTURE_DECISIONS.md` §3, with the date.
- Editorial fixes (typos, links) need no version bump.
- Requirement, acceptance, permission and ADR identifiers are never renumbered or reused.

## 5. Traceability
- FR/NFR IDs (`01_SRS.md`) → acceptance tests AC-xxx (`01_SRS.md` §7) → gate (`04_IMPLEMENTATION_PLAN_CLAUDE_PRO.md` §3).
- Permission action IDs (`PERMISSION_MATRIX.md`) → each API route declares exactly one → table-driven test AC-025.
- ADR-xxx and OD-xx are referenced from the requirements they govern.

## 6. Version history
| Version | Date | Summary |
|---|---|---|
| v0.1 draft | 31 Oct 2026 | Initial drafts of SRS, architecture, database design and implementation plan |
| v1.0 baseline | 31 Oct 2026 | Multi-tenancy model; SYSTEM_ADMIN platform plane with safe bootstrap; roles ORG_OWNER/ORG_ADMIN/ORG_MEMBER/VIEWER and permission matrix; scheduling/result semantics; SSRF hardening; Phase 2 Alloy boundary; DB isolation review; gates reordered (identity → admin → organizations → monitoring); new PERMISSION_MATRIX, ARCHITECTURE_DECISIONS and this index |

## 7. Scope reminder
These are planning documents only. They do not authorize creating databases, applying migrations, running seeds, provisioning paid services or deploying. Those actions need explicit Product Owner approval at the relevant gate.
