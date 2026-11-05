# Windows regression report — 2026-10-26

Final v5 source: **PASS 66, SKIPPED 13, FAIL 0**, 79 unittest methods,
33.622s test time. Full logs and source hashes are
`windows-regression-v5.stderr` and `windows-regression-v5.json` under
`.tmp/appliance-inventory-20261026/`. Platform skips cover Linux permissions,
links, special files, process signals and Bash contracts; they are not passes.

Initial inventory failures were corrected without relaxing Linux checks.
The first tests recorded 11 passes, 3 skips, 2 failures and 3 errors. A later
whole-suite attempt timed out at 300 seconds and included a process-death
fixture ERROR. That partial log remains. Intermediate successful source epochs
and final counts are distinguished in the [test ledger](2026-10-26-appliance-tests.md).

The actual service compile through Git Bash failed its initial 900-second
deadline. The guarded low-priority retry also failed its 300-second deadline;
its process tree was stopped. No successful actual snap-helper compile or
ARM64 compile is claimed in this continuation. Build-contract unit tests use
test doubles and do not change this result.

Fresh complete Go and browser suites: **NOT TESTED** here; runtime/UI inputs
were unchanged. Previous source-specific results remain in the preserved
[recovery Windows report](2026-10-26-recovery-windows.md). No commit/push or
production deployment was performed.
