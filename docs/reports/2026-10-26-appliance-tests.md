# Regression and build report — 2026-10-26

## Final code validation

| Executed check | Status | Evidence/result |
|---|---|---|
| Windows complete Python suite, final v5 | PASS / SKIPPED | 66 passed, 13 skipped, 79 total; 33.622s test time |
| Ubuntu complete Python suite, final v5 | PASS | 79 passed, 0 skipped; 156.888s test time |
| Linux real SIGTERM collector test | PASS | Sparse isolated fixture; blocked partial report retained; source file preserved |
| Linux FIFO/symlink manifest refusal | PASS | Rejected before opening special inputs |
| Snap shell contracts | PASS on Ubuntu | Fake Go/Snapcraft: target/compiler/path validation, missing output, failure propagation, preservation and all 8 projects |
| Build-helper Bash syntax | PASS | `shell-syntax` log; wrapper also parsed/executed by contract tests |
| YAML parsing | PASS | 8 recipes and 2 workflows; PyYAML 5.4.1 |
| First real Linux AMD64 service compile via helper | FAIL | 900-second timeout; owned compiler descendants cleaned up |
| Guarded real helper compile, Linux amd64 | FAIL | 301.837s; 300-second build deadline exceeded |
| Guarded real helper compile, Linux arm64 | NOT TESTED | Earlier target did not pass; no second build started |
| Actual .snap packaging / signed image | BLOCKED | Snapcraft and ubuntu-image absent from VM; no image built |
| Physical ARM64 execution, confinement, boot/recovery | NOT TESTED | No qualifying hardware/image supplied |

Windows skips are platform-specific: five inventory link/signal/special-file
cases, seven Linux Bash contracts, and one existing Linux admission-permission
case. A skipped case is not counted as passed. Source hashes for the final
Windows/Ubuntu inputs are retained under the raw evidence directory.

Real compile outputs, if PASS above, cover the actual `aegis-radius` payload with
the shared helper and exact compiler. They are not full application/snap/image
test suites, not native ARM64 execution, and not signed candidate admission.

## Earlier attempts retained separately

- Initial inventory tests: 19 methods, 11 passed, 3 skipped, 2 failures and 3
  errors. Windows legacy ctime and short-path fixture differences were repaired;
  Linux ownership/link semantics were not weakened.
- Intermediate full Python epochs: Windows 63/4 skips (67), then 64/11 (75),
  66/11 (77), and a successful retry of 66/12 (78). Ubuntu 67/0 and 78/0 preceded
  final 79/0. These are separate runs, not additive distinct coverage counts.
- One Windows 78-method attempt hit the 300-second harness limit after an
  existing process-death fixture ERROR during the slowdown. Partial logs remain.
- Initial live inventory was stopped after approximately
  1485.396s; no complete manifest was produced.
  The later bounded run returned BLOCKED after 12.636s of collection;
  it read 32 MiB but completed zero file hashes. The expected fail-closed behavior
  passed; full real inventory collection did not.
- The first deployed smoke batch was 16 PASS / 5 FAIL; retry was 21 PASS.
  FreeRADIUS watchdog/restart events remain an operational FAIL.

## Historical tests not repeated

No Go/runtime/UI/database source changed here. Fresh full Go, browser, PostgreSQL,
candidate API and throughput/load tests are **NOT TESTED in this continuation**.
Their prior records remain intact: [Windows](2026-10-26-recovery-windows.md),
[Ubuntu](2026-10-26-recovery-ubuntu.md),
[PostgreSQL](2026-10-26-recovery-postgresql.md),
[prior recovery/API implementation](2026-10-26-recovery-implementation.md).
Those include source-specific recovery/affected Go checks and isolated 220-check
SQLite and PostgreSQL API runs; they do not certify the new snap packages.
The historical broader Windows Go suite and browser evidence are linked there.

The measured times here describe tests and this constrained environment. No NAS
packet-throughput, production latency SLO, max-capacity or soak result is claimed.
