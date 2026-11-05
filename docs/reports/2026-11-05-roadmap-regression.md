# Windows and Ubuntu regression evidence - 2026-11-05

| Execution and scope | Status and result |
|---|---|
| Windows Go, current dependency | PASS all-package coverage: 52/52 packages; 1,457 test/subtest passes, five SKIPPED. |
| Initial aggregate Go command | FAIL: outer harness deadline of 1,800s. No assertion failures recorded before termination. |
| Complete remaining-package rerun | PASS: all tests in the remaining 11 packages; 41 completed packages reused after input hashes were verified. Counts exclude incomplete original package events. This is not one successful aggregate invocation. |
| Current go vet | PASS, 40.970s. |
| Windows AMD64, Linux AMD64, Linux ARM64 builds | PASS, ten commands each; PE/ELF machine types verified. 23.870s / 133.697s / 134.495s. |
| Final TypeScript / Vite builds | PASS, 11.361s / 8.282s. |
| Final browser suite after dependency and fixture updates | PASS: 37/37, zero failures/skips/flaky; 63.013s. React missing-key warning absent. |
| First browser attempt after final patch | FAIL: 36 PASS / one initial Access Settings navigation timeout. A separate full rerun with unchanged 30s test/10s expectation limits passed 37/37. Initial page rendering remains sensitive to local startup/load; the failed trace is retained. |
| Earlier November 5 browser attempts | FAIL: initial 34 PASS / three setup/navigation timeout FAIL. Separate same-deadline retry 3/3 PASS, full warmed rerun 37/37 PASS. Those preceded the final patch. |
| Windows Python October 29 | Historical PASS: 91 PASS / 17 SKIPPED, 108 discovered. Relevant Python sources unchanged on November 5. |
| Ubuntu Python October 29 | Historical PASS: 108/108, zero skips. Relevant uploaded source hashes retained. |
| Fresh Ubuntu Go / PostgreSQL hosted checks | NOT TESTED at checkpoint preparation. Results must come from actual branch workflows, not local cross-compilation. |

Windows Go skips: TestPostgreSQLLiveMigrationsAndRollback, TestPostgreSQLAccountingLiveFixture, TestPostgreSQLModuleLiveFixture, TestRecoveryLinuxTrustBoundary, TestLiveIANAAssignment.
Three require isolated PostgreSQL, one requires Linux and one requires production
IANA assignment data. No skip is counted as a pass. Go used CGO disabled,
GOMAXPROCS=2, one build worker and Go 1.26.10. Browser tests use mocked APIs and
an owned Vite test server; they are not live device acceptance.

Normal cross-builds do not prove Pi execution, full Snapcraft/image packaging or
the previously timed-out trimpath helper build. All earlier unsuccessful attempts
remain intact. Raw command/event logs, browser traces and result files are retained
under `.tmp/checkpoint-20261105/`; [machine-readable results](2026-11-05-roadmap-results.json)
record exact scope and timing. No throughput, sustained soak or power-loss result
is inferred from build/test durations.
