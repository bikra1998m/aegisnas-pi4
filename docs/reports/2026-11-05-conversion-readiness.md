# Database conversion continuation — 2026-11-05

**Isolated conversion rehearsal: PASS. NAS-0008: Partial. Production release: BLOCKED.**

Final update: all three hosted workflows passed on source `3a93e7027b1a8cc820a0f820dac56aa874323d9a`.
See the [final GitHub validation](2026-11-05-conversion-github-final.md) for current
full-suite counts, PostgreSQL 14/18 CLI results and release-security evidence.
The preparation observations below retain their original scope.

The next independent NAS-0008 software gap now has a working CLI and real database
evidence. `rehearse-sqlite-to-postgres` snapshots the source read-only, migrates the
copy, creates a new private PostgreSQL schema, imports transactionally, and verifies
all 181 table counts/content digests, constraints and sequence high-water marks.
It preserves source files and active configuration. Precision loss is rejected by
default; explicit opt-in reports timestamp truncation and REAL rounding counts.

| Actually executed scope | Result |
| --- | --- |
| Windows PostgreSQL 18.6 conversion unit/integration suite | PASS: 25 tests/subtests |
| Ubuntu VM PostgreSQL 14.24 conversion unit/integration suite | PASS: 25 tests/subtests |
| Actual Windows conversion CLI | PASS: 16 checks; 16.502 seconds |
| Actual Ubuntu conversion CLI | PASS: 16 checks; 51.531 seconds |
| Existing Windows admin CLI unit suite | PASS: 36 tests/subtests |
| Vet for database and admin CLI packages | PASS |
| Windows AMD64/Linux AMD64 admin builds and native Linux database test build | PASS |
| Python CLI fixture syntax | PASS |
| VM service identities before/after both fixture attempts | PASS: eight unchanged |
| Current-commit full hosted Go/Python/browser/PostgreSQL/security and ARM64 build | NOT TESTED at preparation; tracked after publication |
| Production conversion/cutover, HA, long soak and hardware certification | NOT TESTED; release BLOCKED |

Each final executed local/VM suite has zero failures and zero skips. These are
small isolated fixtures (181 tables and 109 rows in each actual CLI fixture), not
production capacity or RPO/RTO measurements. PostgreSQL durability settings remained
`fsync=on`, `full_page_writes=on`, `synchronous_commit=on` on the Ubuntu fixture.

The first Ubuntu run failed: 23 passing and two failed test/subtest events (one
failed case plus its parent). PostgreSQL canceled the initial all-table TRUNCATE
after the unchanged 30-second statement timeout. The initial CLI phase was NOT TESTED
because its prerequisite failed. Replacing that operation with transactional DELETE
of bootstrap rows avoided empty-table/index rewrites. The same Windows/Ubuntu suites
then passed with the original timeout. Failed logs remain separate from retries.
An earlier read-only SSH progress request also timed out during authentication;
the next request recovered access without a reboot or deployment change.

All 169 prior reports and the original working tree were preserved. Entry root HEAD:
`7004511cfbea5f30d53db9b6ac768e059d7cfaf1`; development parent: `d90a7bb8a30cee3e715cb1277fa3aeb5d2ee77b1`.
There were 492 existing status entries and no staged changes. Publication uses the
existing isolated development worktree; no root reset or force push is performed.

The bounded schema-1-to-103/current-schema rehearsal checklist item is supported by
executed fixtures. Authentic historical release database certification, final source
synchronization, production activation/rollback, service/SQL-module rollout, backups,
HA/outage/soak and operational acceptance remain open. This command is not a generic
custom-schema converter: custom indexes/constraints/business rules are not certified.
The receipt always says `production_activation_authorized: false`.

NAS-0116 is still first unfinished in dependency order; NAS-0008 remains the next
independent track and is Partial. NAS-0099 still depends on it. All 135 roadmap
classifications stay **90 Complete / 21 Partial / 24 Missing**, including Partial
telecom NAS-0092–0097. Existing Complete labels do not establish production hardware
certification. Remaining work includes software as well as infrastructure.

The earlier same-day OS evidence still has 9,685 blocking installed-package
occurrences (1,019 distinct IDs across 23 packages); runtime reachability is NOT
TESTED. No VM OS packages were changed. Trusted signing execution, full-image/snap/
firmware evidence, coordinated authenticated activation/recovery, approved governance
and security/hardware review still block release. This conversion does not waive them.

See [operator guide](../sqlite-postgresql-conversion.md),
[implementation/history reconciliation](2026-11-05-conversion-implementation.md),
[exact results](2026-11-05-conversion-results.json),
[changed files](2026-11-05-conversion-changes.csv),
[all milestone assessments](2026-11-05-conversion-milestones.csv),
and [raw evidence hashes](2026-11-05-conversion-evidence.json).
