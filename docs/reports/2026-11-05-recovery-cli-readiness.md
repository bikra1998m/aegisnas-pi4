# Recovery CLI continuation and release readiness — 2026-11-05

**Release: BLOCKED. NAS-0116: Partial. Roadmap: 90 Complete / 21 Partial / 24 Missing.**

Final update: source `d4f87439fcdf74c584cbcdc0f0bfa03309214948` passed all three hosted workflows.
See the [final publication and validation report](2026-11-05-recovery-cli-github-final.md)
for executed full-suite counts, PostgreSQL/browser/security evidence and the larger
VM fixture. Preparation observations below retain their original scope.

This continuation repairs verified defects in the legacy SQLite backup/restore
commands. It does not complete all enterprise milestones or authorize a production
release. The Ubuntu deployment is preserved; tests use new private fixture paths.

| Executed check | Result |
| --- | --- |
| Windows complete `cmd/aegis-admin` suite | PASS: 36 tests/subtests, zero failures/skips |
| Ubuntu complete `cmd/aegis-admin` suite | PASS: 36 tests/subtests, zero failures/skips |
| Windows actual legacy backup/restore CLI | PASS: 36; SKIPPED: one Linux permissions check |
| Ubuntu actual legacy backup/restore CLI | PASS: 37; zero failures/skips |
| Windows existing sealed recovery CLI | PASS: 23; SKIPPED: one Linux permissions check |
| Ubuntu existing sealed recovery CLI | PASS: 24; zero failures/skips |
| CLI vet and Windows AMD64/Linux AMD64/Linux ARM64 builds | PASS |
| New fixture Python syntax | PASS |
| Deployed Ubuntu service identities before/after | PASS: all eight unchanged |
| Current source hosted full regression, PostgreSQL, browser, dependency scans | NOT TESTED at preparation; tracked in the subsequent publication report |
| Production activation, power loss, full image, real hardware | NOT TESTED; release BLOCKED |

The new local checks passed before publication. Hosted results must be read from
the later report for the exact new commit, not inferred from the earlier checkpoint.
The earlier full Windows/Ubuntu/browser/PostgreSQL/security results and their failed
attempts remain in [the previous checkpoint](2026-11-05-roadmap-github-security-final.md).

The prior fresh OS inventory still blocks 9,685 high/critical occurrences across
23 installed packages, with 1,019 distinct blocking IDs. This is installed-package
evidence, not a finding that all occurrences are reachable in the shipped runtime.
No OS package, service, production database or security policy was changed here.
Full image/snap/firmware coverage, trusted signing execution, coordinated activation
and every restore entry point, governance, security review and hardware certification
remain open. The five previously observed live readiness blockers remain unresolved.

NAS-0116 remains the first unfinished dependency-ordered milestone; NAS-0008 is the
next independent implementation track. SQLite-to-PostgreSQL conversion, production
SQL module/write validation, HA/outage/soak and operational certification remain.
Telecom NAS-0092–0097 remain Partial without the required live enforcement/hardware
evidence. Existing Complete labels are engineering classifications, not fresh
production certification of every item.

Reports: [implementation/history reconciliation](2026-11-05-recovery-cli-implementation.md),
[Windows/Ubuntu/live validation](2026-11-05-recovery-cli-tests.md),
[machine-readable results](2026-11-05-recovery-cli-results.json),
[exact changed files](2026-11-05-recovery-cli-changes.csv),
[evidence hashes](2026-11-05-recovery-cli-evidence.json).
