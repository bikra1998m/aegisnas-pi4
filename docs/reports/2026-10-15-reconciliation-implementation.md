# Current implementation audit

This continuation preserved the existing NAS-0116 implementation and audited the original development history before making focused changes. **NAS-0116 and NAS-0008 remain Partial.** There is no new completed milestone or release claim.

## Repository and implementation history

Branch `main`, HEAD `7004511cfbea5f30d53db9b6ac768e059d7cfaf1` (`test(ui): stabilize NAS-0097 docsis access settings flow`). A read-only `git ls-remote` confirmed remote main at the same commit. No commit, reset, checkout replacement, push or force-push was performed. No applicable AGENTS.md was found in the repository/parent search.

The entry working tree contained **64 changed/new non-report files and 12 report files**. The earlier 67-row modified-file ledger included three older reports, so its count must not be described as 67 non-report files. This continuation captured entry Git status and hashes of 1,241 tracked/unignored files before editing. All 12 entry report files remain byte-for-byte unchanged, and all **164** artifacts in the earlier NAS-0116 raw-evidence manifest still match their hashes. Changes since entry and all current non-report working-tree changes are enumerated with hashes in the companion CSV files linked from the readiness report. Earlier report source hashes deliberately describe their earlier snapshot; they are not rewritten to conceal these new edits.

Initial process inspection found the VMware VM and an unrelated Codex browser runtime, with no ongoing test/scanner/API/PostgreSQL process to resume. The browser runtime was left alone. New tests used isolated directories and private database instances. No deployed binary, FreeRADIUS configuration or production database was changed.

## Changes made in this reconciliation

| Files | Behavior / reason |
|---|---|
| `scripts/analyze_go_exposure.py`, `scripts/test_analyze_go_exposure.py` | New non-waiving exposure analysis and eight tests; compare affected advisory packages with shipped command imports while retaining scanner/source provenance. Unknown metadata stays unknown. |
| `.github/workflows/release-candidate.yml` | Require both expected architectures and call the actual staging admission path with runner-owned policy before verified artifact upload; include admission receipts. Hosted signing remains unexecuted. |
| `internal/db/nas_clients.go` | Portable Boolean predicates/literals, timestamp-to-text projection and PostgreSQL-native timestamp ordering. Summary timestamp query errors now propagate. No schema change or generic SQL rewriting added. |
| `internal/db/nas_clients_test.go`, `internal/db/postgres_integration_test.go` | Share meaningful lifecycle/rejection/expiry assertions across SQLite and actual PostgreSQL; cover lists, approval/refresh, heartbeat, event timestamps and revocation. The live test owns a unique schema and rolls back/cleans up only its own data. |
| Master roadmap, engineering backlog, NAS-0008 and NAS-0116 checklists, supply-chain guide | Reconcile historical requirements, record new scope, remove stale NAS-0008/Phase 0 completion claims, retain Partial classifications and describe the exposure command. |
| New `docs/reports/2026-10-15-reconciliation-*` and history report | Distinct current-session evidence, old snapshots, failures, security decision, roadmap and release-readiness assessment. |

The prior dependency upgrades, PostgreSQL migration/seed/audit fixes, admin API/UI integration, release-security tools, old reports and unrelated local changes were preserved. Dependency lockfiles and UI source were not changed in this reconciliation.

## Functional findings

The first added PostgreSQL runtime tests failed on `boolean = integer` and timestamp `COALESCE(..., '')`. After those fixes, event listing exposed `datetime(timestamp with time zone)`. Both failed attempts are preserved. Final focused PostgreSQL tests pass on Windows PostgreSQL 18.6 and VM PostgreSQL 14.24. SQLite and DB/API regression evidence is reported separately; no success is inferred from a planned test.

The release workflow previously checked signatures without running the full artifact admission path. It now exercises signature, source/platform/sequence, payload-manifest, evidence and extraction validation together before upload. Static workflow checks and mocked admission tests do not substitute for actual signed artifacts.

Current package-import evidence explains why a module advisory is not an observed shipped affected-package import. It leaves the conservative release block unchanged.

## Remaining implementation risk

NAS-0008 still has other runtime SQL portability gaps, including `enabled = 1` predicates in NAS session ownership, plus missing SQL accounting and authentication/session integration coverage. Passing the lifecycle slice does not close the production data plane.

NAS-0116 still needs safe production activation and authenticated database/config rollback, monotonic-floor lifecycle, whole-image evidence and approved exception/SLA/retention governance. The existing offline restore script is not treated as certified recovery. Further details and missing external prerequisites are in the [NAS-0116 gap report](2026-10-15-reconciliation-nas0116.md).

The [historical reconciliation](2026-10-15-history-reconciliation.md) records architectural requirements and superseded assumptions. The [readiness assessment](2026-10-15-reconciliation-readiness.md) indexes all test reports, exact changes and remaining roadmap rows.
