# Published conversion checkpoint and final test results — 2026-11-05

**Development checks: PASS. NAS-0008: Partial. Overall release: BLOCKED.**

Source commit [`3a93e7027b1a8cc820a0f820dac56aa874323d9a`](https://github.com/bikra1998m/aegisnas-pi4/commit/3a93e7027b1a8cc820a0f820dac56aa874323d9a)
is published on `codex/roadmap-checkpoint-20261105`. All three hosted workflows
completed successfully: [PostgreSQL runtime compatibility](https://github.com/bikra1998m/aegisnas-pi4/actions/runs/42020301461); [Release candidate security](https://github.com/bikra1998m/aegisnas-pi4/actions/runs/42020301253); [CI](https://github.com/bikra1998m/aegisnas-pi4/actions/runs/42020301404). This supersedes the preparation report's NOT TESTED
hosted entries, while preserving earlier unsuccessful attempts as separate evidence.

| Current executed scope | Result |
| --- | --- |
| Full Ubuntu Go suite | PASS: 1,512 test/subtest events; five SKIPPED; zero failures |
| Ubuntu Python suite | PASS: 108/108; zero skips |
| Full browser suite / frontend build | PASS: 37/37; zero failures, skips or flaky tests |
| PostgreSQL 14 and 18 runtime/migration/conversion matrices | PASS: 181 test/subtest events each; zero failures/skips |
| Actual conversion CLI on both hosted PostgreSQL versions | PASS: 16 checks each, 181 tables and 109 rows verified |
| Real FreeRADIUS/PostgreSQL accounting/authentication fixture | PASS: 117 checks |
| Existing legacy and authenticated recovery CLI fixtures | PASS: 37 and 24 checks in ordinary CI and release workflow |
| Windows PostgreSQL 18.6 conversion suite / actual command | PASS: 25 / 16 checks |
| Actual Ubuntu VM PostgreSQL 14.24 conversion suite / command | PASS: 25 / 16 checks on corrected source |
| Existing Windows admin CLI unit suite / database and CLI vet | PASS: 36 tests/subtests; vet passed |
| Linux AMD64 and ARM64 release candidates | PASS: hosted build/upload; independent downloaded-archive verification NOT TESTED in this slice |
| Complete clean-source dependency gate | PASS: zero findings; 65 Go and 184 npm components; source identity/output hashes checked |
| Trusted signing/admission execution | SKIPPED by manual-main restriction |
| VM deployed-service continuity | PASS: eight identities unchanged after both failed and passing fixture attempts |

Full-suite skips: TestSQLitePostgreSQLConversionLive, TestPostgreSQLLiveMigrationsAndRollback, TestPostgreSQLAccountingLiveFixture, TestPostgreSQLModuleLiveFixture, TestLiveIANAAssignment. The separate PostgreSQL workflow
provides actual live fixtures for its stated scope; it does not relabel those skips.
Extra vendor/registry/broadband/DOCSIS contract targets passed as separate CI steps
and are not double-counted in the full-suite total. Earlier full Windows results
remain historical to their source checkpoints; the changed conversion/database
scope and existing admin CLI were executed on Windows here.

The new command snapshots the original SQLite source without upgrading it in place,
upgrades a private copy, imports into a newly created owner-only schema and checks
every table count/content digest. Foreign keys are validated and their original
modes restored. Sequence restart preserves deleted-ID high-water values. Precision
loss requires explicit opt-in and is counted. Existing schemas, live service config,
and the deployed NAS/FreeRADIUS data were not modified. The receipt explicitly says
`production_activation_authorized: false`.

Measurements: the corrected actual-command fixture took
16.502 seconds on Windows and
51.531 seconds on the Ubuntu VM; hosted PostgreSQL 14/18
fixtures took 6.697/5.557 seconds. These runs
cover 181 mostly empty tables and 109 rows, including large counters, deleted IDs
and precision cases. They are not production throughput, capacity or RPO/RTO SLAs.
VM PostgreSQL retained fsync, full-page writes and synchronous commit, all enabled.

Preserved FAIL evidence: the original VM run recorded 23 pass and two fail events
(one case and its parent). A cold all-table TRUNCATE exceeded the original
30-second statement timeout. The fix deletes bootstrap rows transactionally, avoiding
empty relation/index rewrites. Windows and Ubuntu reruns passed with the same timeout.
The initial VM actual-CLI phase was NOT TESTED because its prerequisite failed. A
separate initial SSH progress request hit a 30-second authentication timeout; access
recovered on retry. No reboot or change to production services was used to obtain a pass.

The bounded schema-1-to-103/current-schema rehearsal item is now implemented and
tested. NAS-0008 remains Partial: authentic historical release artifact conversion,
final synchronization, production cutover/rollback, service/device/SQL-module
acceptance, authenticated PostgreSQL backup orchestration, HA/outage/soak and
operational certification remain open. Custom source constraints/indexes/business
rules are not certified. The conversion command is not a production activator.

The overall release gate remains BLOCKED. The earlier same-day OS scan records
9,685 high/critical installed-package occurrences, comprising 1,019 distinct IDs
across 23 packages; runtime reachability is NOT TESTED. VM packages were unchanged.
See [OS/security evidence](2026-11-05-roadmap-github-security-final.md). Full-image,
nested snap and firmware evidence, real trusted signing, coordinated authenticated
activation/recovery, Store/model identities, RADIUS confinement, approved governance,
independent security review and hardware certification remain prerequisites. No
production deployment, package upgrade, main merge or additional reboot occurred.

Roadmap: **90 Complete / 21 Partial / 24 Missing**. NAS-0116 remains first unfinished;
NAS-0008 is the next independent Partial track and NAS-0099 depends on it. Telecom
NAS-0092–0097 remain Partial. Complete labels are historical engineering classifications,
not new certification of every feature. Remaining work includes software and external
infrastructure; it is not all blocked solely by credentials.

The source commit changes 18 files: five Go implementation/test files, one actual-CLI
fixture, one CI workflow, five guides/roadmap/checklist files and six reports. See
[the exact change ledger](2026-11-05-conversion-changes.csv). All 169 prior reports
remain byte-identical. The root remains on `main` at `7004511cfbea5f30d53db9b6ac768e059d7cfaf1` with
its unrelated local changes and no staged files. Publication uses the isolated
development worktree. This report is a documentation-only follow-up with `[skip ci]`;
executed evidence remains bound to the source commit above.

See [operator guide](../sqlite-postgresql-conversion.md),
[historical/implementation reconciliation](2026-11-05-conversion-implementation.md),
[local/VM report](2026-11-05-conversion-readiness.md),
[machine-readable hosted results](2026-11-05-conversion-github-results.json),
[consolidated roadmap](2026-11-05-conversion-milestones.csv),
and [final evidence hashes](2026-11-05-conversion-final-evidence.json).
