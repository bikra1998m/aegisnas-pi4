# Windows regression — October 23

Go 1.26.10, CGO disabled, Windows AMD64. Full `go test ./... -count=1 -json -timeout=30m`: **1414 PASS, 0 FAIL, 3 SKIPPED**. The newly added live-module fixture explicitly skips without its opt-in environment; the real fixture ran separately on Ubuntu. Prior full suites are not added to these counts.

| Command | Status | Exit | Seconds |
|---|---|---:|---:|
| windows-go | PASS | 0 | 841.158 |
| windows-build | PASS | 0 | 24.864 |
| linux-build | PASS | 0 | 24.071 |
| arm64-build | PASS | 0 | 66.713 |
| linux-adminapi-test-build | PASS | 0 | 73.567 |
| vet | PASS | 0 | 73.859 |
| python | PASS | 0 | 5.776 |

Additional focused package runs and earlier compilation attempts are retained in `.tmp/production-20261023/`; they are not counted a second time in the full-suite total. Python security tests cover the existing release gate, OS gate and admission behavior. Native Linux execution is reported separately; cross-build success alone is not a runtime PASS.

Historical October 22 evidence: PostgreSQL 18.6 runtime/migration matrix 152 PASS; built browser suite 37 PASS (mocked APIs), frontend build PASS. These unchanged database/UI suites were not repeated on October 23. No new browser or database-matrix execution is claimed.
