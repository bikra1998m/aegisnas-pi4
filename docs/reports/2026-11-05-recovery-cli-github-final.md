# Published recovery checkpoint and final validation — 2026-11-05

**Development regression: PASS. Production release: BLOCKED. NAS-0116: Partial.**

Tested and pushed source: [`d4f87439fcdf74c584cbcdc0f0bfa03309214948`](https://github.com/bikra1998m/aegisnas-pi4/commit/d4f87439fcdf74c584cbcdc0f0bfa03309214948)
on `codex/roadmap-checkpoint-20261105`. All three workflows passed: [Release candidate security](https://github.com/bikra1998m/aegisnas-pi4/actions/runs/42002461541); [CI](https://github.com/bikra1998m/aegisnas-pi4/actions/runs/42002461866); [PostgreSQL runtime compatibility](https://github.com/bikra1998m/aegisnas-pi4/actions/runs/42002461523).
The earlier preparation reports' NOT TESTED hosted entries are superseded by these
executed results, bound to this exact commit.

| Actual executed scope | Result |
| --- | --- |
| Full Ubuntu Go suite | PASS: 1,492 test/subtest passes; 4 SKIPPED; zero failures |
| Ubuntu Python suite | PASS: 108/108, zero skips |
| Browser suite and frontend build | PASS: 37/37 tests, zero failures/skips/flaky |
| PostgreSQL 14 and 18 migration/runtime matrices | PASS: 156 test/subtest passes each |
| Real FreeRADIUS/PostgreSQL accounting and authentication | PASS: 117 checks |
| Hosted legacy CLI / sealed CLI fixtures | PASS: 37 / 24 checks in normal CI and release-security workflow |
| CLI unit suite on Windows and actual Ubuntu VM | PASS: 36 tests/subtests on each |
| Windows actual legacy CLI / sealed CLI | PASS: 36 / 23; one Linux-mode check SKIPPED in each |
| CLI vet, Windows AMD64/Linux AMD64/Linux ARM64 builds | PASS |
| Clean committed-source dependency gate | PASS: zero findings; 65 Go and 184 npm components; source SHA and output hashes verified |
| Linux AMD64/ARM64 candidate build/upload | PASS; independent downloaded-archive verification NOT TESTED in this slice |
| Trusted signature/admission execution | SKIPPED by manual-main restriction |
| Ubuntu larger backup/restore fixture | PASS: 7 checks; 50,000 rows and full content digest restored |
| Existing deployed service continuity | PASS: eight identities unchanged through both VM fixture runs |

Full Go skips: TestPostgreSQLLiveMigrationsAndRollback, TestPostgreSQLAccountingLiveFixture, TestPostgreSQLModuleLiveFixture, TestLiveIANAAssignment. The separate PostgreSQL tests supply
their specific live-fixture coverage without relabeling these skips. Additional
vendor/registry/broadband/DOCSIS CI targets passed; their duplicated tests are not
added to the full-suite total. Earlier full Windows and browser results remain
historical to the prior source checkpoint; the changed CLI package and its commands
were executed again on Windows here. No unrelated full Windows rerun was invented.

The larger VM fixture used a 68,440,064-byte SQLite database with
50,000 rows of 1,024 random payload bytes each. Actual backup took
16.082 seconds and produced a 51,976,338-byte
archive; restore took 7.001 seconds. It deleted half
the fixture rows after backup, restored them, and verified all ordered row contents,
integrity, private modes and two retained safety copies. These are single-run fixture
measurements, not a production capacity benchmark or recovery SLA. The scripts and
raw results remain in `.tmp/recovery-cli-20261105/ubuntu-scale/` and its parent.

Preserved FAIL attempts: the original defect reproductions, the first corrected
implementation's Windows URI error, and publication's default whitespace check
which treated preserved CRLF report endings as trailing whitespace. The corrected
URI has regression coverage. The CRLF-aware whitespace check passed without changing
historical report bytes. A report-generation helper initially used the wrong CSV
column name and failed; it was corrected to `CurrentImplementationStatus` before
publication. Earlier checkpoint failures remain in their dated reports.

Security and release decision: dependency validation passed again, but the earlier
fresh VM OS scan still blocks 9,685 high/critical installed-package occurrences
(9,257 high, 428 critical; 1,019 distinct IDs across 23 packages). No package was
upgraded or removed, so that same-day evidence remains applicable. Installed
occurrences include repeated kernel headers/tools/modules and multiple versions;
runtime reachability is NOT TESTED. Whole-image/snap/firmware coverage is incomplete.
See the [OS report and package remediation inventory](2026-11-05-roadmap-github-security-final.md).

The main-only trusted workflow was not bypassed. The requested merge/signing decision
has not arrived, so main and signing remain unchanged; ordinary development-branch
publication was already authorized. No signature or production certification was
fabricated. Remaining software also includes coordinated authenticated activation,
DB/config/binary rollback at every restore entry point and power-loss durability.
Store/model identities, RADIUS confinement, approved exception/SLA/retention policy,
security review and hardware evidence remain prerequisites. No production deployment,
service restart or additional reboot occurred. The five previously observed deployed
readiness blockers are not resolved by these isolated tests.

Roadmap classification remains **90 Complete / 21 Partial / 24 Missing**. NAS-0116
is first unfinished; NAS-0008 is next independent, with SQLite-to-PostgreSQL conversion,
production service/SQL integration, HA/outage/soak and operational acceptance pending.
Telecom NAS-0092–0097 stay Partial. The remaining work is not solely blocked by
credentials: substantial implementation and certification remain. See
[all dependency-ordered milestone assessments](2026-11-05-recovery-cli-milestones.csv).

This source commit changed 18 files: four CLI Go files, the standalone CLI test
fixture, two CI workflows, five operator/roadmap/checklist files and six reports.
The [exact source/docs change ledger](2026-11-05-recovery-cli-changes.csv) records the
12 non-report paths and hashes; Git records the complete commit. The root stays
on `main` at `7004511cfbea5f30d53db9b6ac768e059d7cfaf1` with its prior local changes and no staged
files. All 159 prior reports remain byte-identical. A documentation-only follow-up
records these hosted results with `[skip ci]`; test evidence remains bound to the
source SHA above, not to a new signed release.

See [local implementation and historical reconciliation](2026-11-05-recovery-cli-implementation.md),
[Windows/VM tests](2026-11-05-recovery-cli-tests.md),
[machine-readable final results](2026-11-05-recovery-cli-github-results.json),
and [final evidence hashes](2026-11-05-recovery-cli-final-evidence.json).
