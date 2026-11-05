# Windows regression report

| Execution | Status | PASS | FAIL | SKIPPED |
|---|---|---:|---:|---:|
| Windows full Go 1.26.10 | PASS | 1400 | 0 | 2 |
| Windows PostgreSQL 18.6, Go 1.26.10 | PASS | 152 | 0 | 0 |
| Windows PostgreSQL 18.6, Go 1.26.9 | PASS | 152 | 0 | 0 |
| Windows initial attempt | FAIL | 1056 | 0 | 2 |
| Windows affected-package timeout | FAIL | 989 | 0 | 1 |

| Command | Exit | Seconds |
|---|---:|---:|
| go-version | 0 | 0.513 |
| build-windows | 0 | 22.884 |
| build-linux-amd64 | 0 | 195.926 |
| build-linux-arm64 | 0 | 144.039 |
| vet | 0 | 75.643 |
| python-security | 0 | 1.962 |
| install-govulncheck | 0 | 57.831 |
| install-cyclonedx | 0 | 160.011 |
| security-gate | 1 | 520.133 |
| package-exposure | 1 | 0.571 |

Python security tests: 33 PASS on Windows; the same unchanged scripts also passed 33 tests on Ubuntu. Native Windows and Linux AMD64/ARM64 cross-builds and vet passed. The command ledger retains earlier invalid-snapshot scan attempts separately from the final security report.

Counts are actual test/subtest completion events, not unique product features. Full-suite explicit skips are the optional PostgreSQL DSN test (separately executed on real servers) and live IANA assignment (project enterprise number and organization were not supplied). Packages without test files are not counted as skipped tests.

Production UI preview: **37 PASS, 0 FAIL, 0 SKIPPED, 0 flaky**, exit `0`, 86.078 seconds wall time. Chromium uses the built UI on isolated loopback port 4183, one worker and a 120-second test budget; normal assertion timeouts remain. These browser tests use API mocks; they do not certify an authenticated browser session against the deployed VM. The post-patch build passed and all built asset hashes match those tested. No browser rerun was needed for identical shipped asset bytes.

Earlier attempts remain: npm startup stall; page-creation timeouts; development-server failures (0 passed, 1 failed, 36 skipped on each fail-fast retry); alternative full Chromium launch timeout. Their traces/logs are preserved. The passing preview run does not erase them or certify live devices.

The initial full Go attempt had a mixed-source build error and runner timeout. The later affected-package run timed out in admin API after 30 minutes; it was not a full PASS. The corrected Go 1.26.10 harness selects an absolute toolchain path after an earlier Windows PATH error selected Go 1.26.2. An interrupted ARM64 build was resumed separately; only recorded exit codes count.

Raw evidence: `.tmp/production-20261022/patched-validation2/`, `pg-matrix-patched/`, `windows-live-api/`, `ui-preview/`, `ui-asset-comparison.json`; prior attempts retain their separate directories.
