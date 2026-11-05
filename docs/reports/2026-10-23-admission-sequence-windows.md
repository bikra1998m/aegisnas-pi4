# Windows admission regression

**PASS: 47 tests. SKIPPED: 1 Linux ownership/link test. FAIL: 0.** Final command: `python -m unittest discover -s scripts -p 'test_*.py' -v`; duration 14.773s. Authoritative raw output: `.tmp/admission-guard-20261023/windows-final2.stderr`; result and exact script hashes: `windows-final2.json` in that directory.

All 23 admission tests are collected, including the 15 added cases. Real subprocess and filesystem tests exercise the persistent floor and lock. Other existing scanner, OS-gate and exposure-analysis tests also ran. This Windows suite does not certify POSIX ownership, directory fsync, actual power-loss recovery or trusted GitHub signatures.

Earlier attempts are retained: `windows-first.log` ran the original 8 admission tests and hit the read-only fsync descriptor error; `windows-second.stderr` collected 48 with 38 PASS, 4 FAIL, 5 ERROR and 1 SKIPPED due to that same defect. `windows-third`, `windows-final` and `windows-final2` are separate subsequent epochs; only final2 identifies the final code. Counts are not cumulative.

Earlier application evidence, not rerun here: October 23 full Go suite **1,414 PASS / 3 SKIPPED**, Windows/Linux AMD64/Linux ARM64 builds and go vet PASS. All 904 Go/dependency input hashes match that tested source. October 22 browser **37 PASS** remains earlier evidence; no frontend change was made here. See [earlier Windows report](2026-10-23-continuation-windows.md). No claim of a fresh full Go or browser run is made.
