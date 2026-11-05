# PostgreSQL integration report

**PASS for the executed migration and NAS-client lifecycle slice. NAS-0008 remains Partial.** Tests used real PostgreSQL, not a SQL mock or migration-text inspection.

## Current-session execution

| Attempt | Status | Observed result |
|---|---|---|
| Windows 18.6, `pg-before/test.log` | FAIL | Three new subtests failed: Boolean/integer comparison in summary; timestamp empty-string coercion in template/enrollment reads. Parent test failed. |
| Windows 18.6, `pg-after/test.log` | FAIL | Capability rejection and expiry passed; lifecycle failed on SQLite `datetime()` in PostgreSQL event ordering. Parent test failed. |
| Windows 18.6, `pg-final/test.log` | PASS | Parent and all three subtests pass, no skips. Start/test/stop commands exit zero. |
| Ubuntu PostgreSQL 14.24, `vm-postgres-live.log` | PASS | Parent and all three subtests pass, no skips. Private cluster init/start/test/stop commands exit zero. |

All paths above are under `.tmp/reconcile-20261015/`. Counts are four Go pass events in each final live run (one parent plus three subtests), not four independent database installations. Exact command durations and output hashes are in the results/manifest files. The Windows final command took 8.721 seconds; the VM command took 142.404 seconds including compilation, while its Go test package reported 11.747 seconds. These are test execution timings, not database throughput measurements.

The parent test still executes all **101 migrations twice**, seeding twice, quoted audit identifier reads/statistics, Boolean template retrieval, placeholder binding and transaction rollback. The added subtests exercise:

1. Enrollment creation, pending list, capability-template list, approval with secret reference, approved enrollment refresh, enabled/dynamic summary, heartbeat persistence, event timestamp retrieval, revocation and disabled-client count.
2. Required capability enforcement: missing `coa.disconnect` rejects approval.
3. Enrollment expiry and persisted expired status.

Assertions are shared with the SQLite tests, preserving the existing backend behavior. Fixes are limited to `internal/db/nas_clients.go`: portable `TRUE`/`FALSE`, text projection of nullable timestamp columns, dialect-specific ordering and surfaced summary query errors. No schema migration or blanket SQL substitution was introduced.

## Isolation and cleanup

Each live test uses a unique `aegis_integration_*` schema with deferred cleanup. Windows reused only the known stopped local test cluster and wrote new attempt logs. Ubuntu initialized a new cluster inside `/home/bikram/aegisnas-reconciliation-20261015/results/`, listening on a private loopback port. Both test servers were stopped after use. Existing NAS databases, services, FreeRADIUS configuration and the prior validation evidence were untouched.

The loopback fixture uses explicitly permitted insecure TLS mode for disposable tests. TLS `verify-full`, certificate validation, production DSN providers and role-hardening are **NOT TESTED** by these runs.

## Historical evidence retained

Earlier PostgreSQL 18.6 and 14.24 migration/seed/audit/rollback passes remain in the original NAS-0116 reports and raw manifest. They did not cover these newly failing runtime operations and were not relabeled as doing so. Previous timeout/authentication/toolchain failures remain retained as earlier attempts.

## Remaining scope

**NOT TESTED / unfinished:** service-wide runtime SQL, NAS session ownership Boolean predicates, SQL accounting, authentication/session workflows, SQLite-to-PostgreSQL migration rehearsal, logical backup/restore, production TLS, role permissions, outages, HA/consensus and accounting soak/load. Those are explicit reasons NAS-0008 stays Partial. NAS-0099 replicated database/consensus work must not be called complete based on these single-node tests.
