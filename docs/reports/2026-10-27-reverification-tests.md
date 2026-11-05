# Windows, Ubuntu and integration validation — 2026-10-27

## Final execution results

| Check | Status | Exact scope |
|---|---|---|
| Windows Python | PASS / SKIPPED | 105 methods: 88 passed, 17 skipped; 20.472s |
| Ubuntu Python | PASS | 105 methods: all passed; 2.123s |
| Re-verification/permission/schema tests | PASS | 26 new methods; Windows platform-only cases skipped |
| Real security-policy integration | PASS | Synthetic clean, finding-bearing and expired records passed/rejected as expected; only signature verifier mocked |
| Published-directory umask regression | PASS on Linux | Original repro failed four directory assertions; final test checks directories and files including receipt |
| YAML syntax | PASS | Eight snap recipes and two workflows |
| Actual trusted signatures / CI attestation | BLOCKED / NOT TESTED | gh absent from tested Windows and Ubuntu PATHs; no trusted positive verification |
| Deployed smoke | FAIL then PASS retry | 19/21 initially; two timed-out routes passed the separate retry |
| Go / frontend builds and browser suites | NOT TESTED this turn | No relevant source/dependency changes; prior build timeouts remain unresolved historical evidence |
| PostgreSQL migration/accounting/full API fixtures | NOT TESTED this turn | No database code changed and no database fixture started |
| Throughput, maximum-artifact capacity, Pi execution | NOT TESTED | Fixture timings are not capacity or SLO certification |

The 17 Windows skips comprise the 13 prior platform-specific cases plus four
new Linux permission/special-file cases. Skips are not counted as passes.
Raw final records: `windows-complete.*`, `ubuntu-complete.*`,
`ubuntu-complete-inputs.json` and `yaml-and-tools.stdout` under
`.tmp/reverification-20261027/`. The source fingerprints match the final files.

## Failures and intermediate epochs retained

1. Linux original admission permission repro: one test with four failed directory
   assertions under umask 002. Production publication modes were fixed.
2. First Linux full suite: 102 PASS / 1 FAIL (103). The extra-file negative fixture
   was itself group-writable, triggering the correct permission rejection before
   the expected checksum error. Fixture modes were made explicit; checks were not relaxed.
3. Boolean-schema repro: 26 tests, 20 PASS / 4 SKIPPED / 2 FAIL. Both booleans were
   accepted as integer 1 before the strict type correction.
4. Initial live smoke: readiness and system-status GETs timed out. Their successful
   retry does not erase the initial failures or constitute a single 21/21 batch.

Intermediate passing runs (20 focused, 102/103 full methods) are separate source
epochs. Do not add them to the final 105-method coverage count. One test-only
placement typo was corrected before Linux execution; earlier Windows source
epochs are retained, and the final source was rerun on both systems.

Historical runtime/database evidence remains in the preserved
[recovery reports](2026-10-26-recovery-readiness.md),
[PostgreSQL report](2026-10-26-recovery-postgresql.md) and
[appliance/build report](2026-10-26-appliance-tests.md). In particular, earlier
220-check SQLite/PostgreSQL API fixtures and broader Go/browser results were
not rerun here and are not presented as current executions. NAS-0008 remains Partial.
