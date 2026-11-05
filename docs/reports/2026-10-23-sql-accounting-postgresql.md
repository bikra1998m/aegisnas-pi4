# PostgreSQL integration and unsuccessful attempts

Implementation and the main regression suites were executed on **October 23, 2026**. This report was reconciled on **October 26** without changing tested runtime sources. October 26 evidence is labeled separately; earlier attempts remain preserved. The filename retains the implementation start date.

**PASS: PostgreSQL 14 and 18.6 functional matrices, 156 and 156 test/subtests.** Fresh/repeated schema-103 migration, retained-row upgrade, existing integer widening, seed, audit, rollback, URI policy and shared accounting/session/identity/policy/vendor lifecycles are exercised on real servers. Each fixture owns its schemas. SQLite-specific migration/seed/vendor tests execute in the ordinary suite.

**FAIL: initial default-durability broad matrices.** The Windows PostgreSQL log records a checkpoint lasting about 1,106 seconds, including roughly 717 seconds syncing 46,603 files. Connection deadlines failed; the Windows shutdown command also timed out before the server subsequently completed shutdown. The Ubuntu matrix/SSH attempt likewise exceeded operational deadlines. The final state check verifies those owned servers stopped. These are retained failures and a production performance/durability concern, not evidence to discard.

The successful broad retries use **owned disposable clusters with fsync disabled** (the final retry reuses only their stopped test data directories) to separate SQL compatibility from tens of thousands of schema/index file flushes on this shared lab storage. They do not validate durability, power loss, crash recovery, production throughput or HA. No installed deployment or production PostgreSQL settings were changed. The independent packet fixture uses normal durability settings, but a successful short packet run is not full production durability certification.

The preceding Ubuntu functional matrix had 152 passes and three failures in owned-schema cleanup (`TestAccessVendorPackEventLifecycle`, `TestAccountingCountersGigawordsAndResetDetection`, `TestBroadbandSubscriberStateEventLedger`), whose 10-second deadline expired. No failure was relabeled. The final retry increases only test teardown to 60 seconds and must still complete cleanup successfully. That preceding run also logged a real PostgreSQL 14 error from an unaliased summary subquery even though API smoke returned HTTP 200. The query was corrected, error propagation added, and populated assertions and the current API run repeated. Server-log review is recorded separately.

Final packet fixture: 117 checks PASS. It runs generated SQL/unlang with the installed accounting policy, real SCRAM/TLS, Start/Interim/Stop, missing Start, delayed Stop, terminal-state and duplicate handling, NAS On/Off scoping, shared-Class session namespaces, exact uint64 snapshots, IPv6, SQL escaping, least privilege, accept/reject post-auth without password storage, missing/unsupported attributes, time fallback, database outage/no acknowledgement and persisted retry, reconnect and wrong trust/hostname rejection. Real Go reconciliation creates and closes sessions; the periodic deployed broker was not replaced.

| Attempt | Status | Error / scope |
|---|---|---|
| 1 | FAIL | valid-generate |
| 2 | FAIL | radius-start-valid-tls |
| 3 | FAIL | radius-start-valid-tls |
| 4 | FAIL | postauth-accept-recorded |
| 5 | FAIL | radius-start-valid-tls |
| 6 | FAIL | reordered-interim |
| 7 | FAIL | 'stop_time' |
| 8 | FAIL | Expecting value: line 1 column 1 (char 0) |
| 9 | FAIL | Command '['/home/bikram/aegisnas-sql-accounting-20261023/db.test', '-test.v', '-test.count=1', '-test.timeout=25m', '-test.skip=^TestMigrate/^TestSeed/^TestVendorIdentity']' timed out after 1500 seconds |
| 10 | FAIL | initdb |
| 11 | PASS | all recorded checks passed |
| 12 | PASS | all recorded checks passed |
| 13 | PASS | all recorded checks passed |

Attempts preserve the URI certificate-path bug, missing fixture policy, incorrect post-auth subsection, overlong SQL line, stale-packet no-op acknowledgement, incorrect fixture end-time/Boolean assertions, broad storage timeout and initdb timeout. Fixes were tested in later attempts without relabeling earlier runs.

A later current-source PostgreSQL 14 matrix had **152 passes and one failure**, `TestAuthenticationChallengeExpiryAcrossBackends`: PostgreSQL canceled an `INSERT INTO schema_version` during migration 102 at the configured statement timeout, before its three expiry subtests ran. The server logged frequent checkpoints. This is consistent with storage contention, but the exact cause was not independently proven. A targeted retry and full matrix retry ran after other host jobs finished, using the same binary, application query limits and owned fsync-off cluster. Their evidence is in `postgres14-retry/`; the failed run remains in `native-verified/`. No production timeout or security policy was weakened.

Historical October 22 logical TLS restore evidence (25 checks, schema 102, 181 table counts) is not a new schema-103 restore certification. Remaining work: existing-data conversion, production role/secret/PKI provisioning, all service writes/outages, lossless billing acceptance where required, database-aware backup orchestration, HA, sustained soak and representative storage/pool benchmarks.

## October 26 default-durability retry

The VM filesystem expanded from 41,424,257,024 to 73,128,038,400 bytes outside this work. This changed the reason for the previous constrained retries. The same verified current-source Linux binary ran in a **new isolated PostgreSQL 14 cluster with default settings**, with actual `SHOW`/`pg_settings` evidence for fsync, full_page_writes and synchronous_commit. Result: **PASS**, 156 passes, zero failures and zero skips. Targeted authentication-expiry results and all lifecycle command exits are in `results.json` and `.tmp/sql-accounting-20261023/postgres14-durable-20261026/`. This adds executed evidence; the earlier Windows/Ubuntu durable failures remain FAIL. It does not establish power-loss, storage-device durability, HA or long-soak certification.

The packet fixture was also executed again against the changed VM environment: **PASS**, 117 checks, in `attempt14-20261026/`. No installed service or production database was replaced. Full `aegis-radius run` startup invokes `radius.ApplyConfig`, which restarts the system FreeRADIUS service; that deployment-level test was not run while release/cutover gates remain blocked.
