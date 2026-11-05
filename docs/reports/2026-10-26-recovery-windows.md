# Windows regression and build report — 2026-10-26

Environment: Windows AMD64, Go 1.26.10, CGO disabled, `GOMAXPROCS=2`, `GOFLAGS=-p=1`.

| Execution | Status and actual count |
|---|---|
| Initial affected suites: upgrade/adminapi/aegis-admin | PASS: 374; SKIPPED: 1 |
| Final upgrade suite after WAL/backend fixes | PASS: 44; SKIPPED: 1 |
| Final API selection: UpgradeReadiness/SupportBundle/Rollback | PASS: 72 |
| Final OpenAPI response contract | PASS: 1 |
| Actual final recovery CLI fixture | PASS: 23; SKIPPED: 1 |
| Python release/security/admission suite | PASS: 47; SKIPPED: 1 |
| Affected-package `go vet` | PASS |
| All command builds, Windows AMD64/Linux AMD64/Linux ARM64 | PASS |
| Final API rebuild after OpenAPI description | PASS on all three targets |
| CI and release-candidate YAML parsing | PASS; hosted execution NOT TESTED |

The Go skip is Linux-specific ownership/mode/link enforcement. The CLI skip is
Linux staging permissions; Windows ACLs are not certified. The Python suite's
platform skip remains explicit in its raw log. No ARM64 binary was executed on
physical hardware. Whole-repository suites for unchanged packages and the prior
37 browser tests were not repeated; earlier results remain separately dated.

Preserved failures: the first CLI compile rejected an int/int64 mismatch, fixed
before successful builds; the optional Python YAML wrapper lacked PyYAML after
unit tests passed. Existing Go YAML parsing subsequently validated both workflows.
The initial Ubuntu permission-fixture failures are in the Ubuntu report.

Raw evidence: `windows-regression.stdout`, `windows-upgrade-v3.stdout`,
`windows-api-recovery-v3.stdout`, `openapi-contract.stdout`, `windows-cli-v3/`,
`go-v3-results.json`, `openapi-final-results.json`, `python-tests.stderr` and
`workflow-validation.stdout` under `.tmp/recovery-security-20261026/`.
