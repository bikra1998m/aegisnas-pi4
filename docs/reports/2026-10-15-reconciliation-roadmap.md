# Consolidated roadmap status

The authoritative engineering backlog still contains **135 milestones: 90 recorded Complete, 21 Partial, 24 Missing**. There are **45 unfinished milestones**, and no milestone was closed in this reconciliation. Recorded Complete is historical engineering status, not a fresh certification of every acceptance criterion or a production-readiness percentage.

The [135-row assessment](2026-10-15-reconciliation-milestones.csv) retains implementation-commit provenance, dependencies, scope and remaining work. The [45-row remaining roadmap](2026-10-15-reconciliation-remaining-roadmap.csv) is in authoritative dependency order.

| Sequence | Milestone | Current state / next action |
|---|---|---|
| 4 | NAS-0116 supply-chain release security | Partial; retain blocking gates; finish activation/authenticated recovery, whole-image coverage and governance, then obtain trusted signing/certification evidence. |
| 6 | NAS-0008 production PostgreSQL data plane | Partial; tested NAS-client runtime slice repaired; next cover NAS session ownership, accounting/authentication and remaining service SQL. |
| 16 | NAS-0099 replicated database and consensus | Missing; depends on NAS-0008; do not equate package replication with consensus. |
| 17 | NAS-0112 Vault/HSM/TPM/envelope encryption | Missing; depends on NAS-0007 and NAS-0008. |
| 20 | NAS-0106 distributed tracing | Missing; depends on NAS-0002 and NAS-0008. |

The master roadmap's stale checked NAS-0008 and Phase 0 exit boxes were corrected to match its summary and backlog. NAS-0092…0097 remain Partial because persistence/configuration/reporting does not demonstrate the promised live telecom data plane. External hardware certification alone does not determine engineering status, but missing live integration software does.

The July archived policy required feature closure to include passing relevant checks, documentation and a Conventional Commit. Neither active milestone is closed here; the existing mixed working tree remains intact and uncommitted. Old archive requests do not authorize a push or another disruptive VM recovery.

See [historical requirements](2026-10-15-history-reconciliation.md), [current implementation](2026-10-15-reconciliation-implementation.md) and [release readiness](2026-10-15-reconciliation-readiness.md).
