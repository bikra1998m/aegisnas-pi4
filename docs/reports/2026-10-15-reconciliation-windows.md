# Windows regression report — current reconciliation

**PASS: 471 Go test/subtest pass events, zero failures, one explicit skip, two packages passed.**

Executed `go test -json -count=1 -timeout=15m ./internal/db ./internal/adminapi` against the current NAS-client changes. The skip is `TestPostgreSQLLiveMigrationsAndRollback` because this regression run has no DSN; the live PostgreSQL run was separately executed and passed. Counts include subtests and must not be added to older full-suite totals as distinct coverage.

| Package | Result | Go-reported package seconds |
|---|---|---:|
| `db` | PASS | 641.782 |
| `adminapi` | PASS | 859.588 |

Raw evidence: `.tmp/reconcile-20261015/windows-regression.jsonl`. Package elapsed time is not the overall wall time or a performance benchmark. The Ubuntu runner's full command duration is separately retained in `vm-results.json`. Windows command completion returned exit zero.

Native command build: **PASS**, 42.486 s. Focused vet: **PASS**, 48.233 s. `git diff --check`: **PASS**.

Python security suite: **PASS**, 33 tests, 2.026 s. This includes the prior 25 release/admission/OS tests and eight new exposure-analysis tests. Signature verifiers in unit fixtures are mocked; no real signature proof is claimed.

Real isolated API/SQLite/built-UI smoke: **PASS**, 15 checks. Its 100 sequential loopback requests measured median 15.063 ms, p95 16.369 ms, maximum 25.852 ms. Scope: missing-admission status endpoint, not RADIUS throughput, disk performance or production load.

## Preserved earlier results

The earlier Windows full Go suite recorded **1,391 passes and two skips**. Those results were hash-verified and are not represented as a new full-suite run. The Windows full suite preceded the prior migration fixes; its later 492-pass affected-package run and the earlier final Ubuntu full suite remain separately recorded. Both old full suites explicitly skipped live PostgreSQL and live IANA assignment. The browser suite remains **37 passes, zero skips/failures/flaky tests**, using mocked API fixtures. UI source/dependencies were unchanged here, so the browser suite was not needlessly repeated.

Earlier failures and the new PostgreSQL failures remain preserved. The initial current Windows auxiliary-check runner failed before executing checks because PyYAML was unavailable; native checks were run after decoupling that dependency, and YAML/static shell checks passed on the VM's existing environment. See the [PostgreSQL report](2026-10-15-reconciliation-postgresql.md) and [readiness index](2026-10-15-reconciliation-readiness.md).
