# Ubuntu regression report — 2026-10-26

Tests used new private workspaces under
`/home/bikram/aegisnas-recovery-20261026` and its `-v3` sibling, on the existing
Ubuntu 22.04 AMD64 VM. Uploaded test/executable hashes matched the Windows-built
Linux artifacts. No repository source or installed service was replaced.

| Execution | Status and actual count |
|---|---|
| Initial upgrade suite | FAIL: 40 passes, 3 failures |
| Initial full admin API suite | PASS: 330 |
| Initial real recovery CLI | PASS: 24 |
| Final complete upgrade suite | PASS: 45, zero failures/skips |
| Final focused API/support/recovery suite | PASS: 72, zero failures/skips |
| Final real recovery CLI | PASS: 24, zero failures/skips |
| Final isolated API suites | PASS: SQLite 220; PostgreSQL 220 |

The three initial failures were positive fixtures using Go `testing.TempDir`
subdirectories made group-writable by the VM umask. The production path checks
correctly refused them. Tests now provision mode-0700 roots. No ownership or
write-permission checks were weakened. Final tests exercise wrong keys, changed
context/digest, altered data, unsafe paths, overwrite rejection, archive bounds,
SQLite integrity, PostgreSQL refusal and committed-WAL rehearsal behavior.

These are package/fixture results, not a fresh whole-repository Ubuntu suite.
The final OpenAPI-only description change was verified separately on Windows;
the final API binary was rebuilt for Linux but not used to repeat these runtime
fixtures. Both API processes and the dedicated PostgreSQL server stopped, and
all eight deployed service PIDs/start timestamps remained unchanged.

Raw stdout/stderr, upload hashes, execution durations and CLI receipts are in
`.tmp/recovery-security-20261026/`; unsuccessful evidence is retained alongside
the `-v3` retry files.
