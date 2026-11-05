# Ubuntu regression — October 23

The changed RADIUS package and its Admin API consumer were cross-built with Go 1.26.10 and executed natively on the Ubuntu VM using the recorded test2json adapter. Binary hashes and exact results are in [machine results](2026-10-23-continuation-results.json). This was not a native VM compiler run.

| Package | Exit | PASS | FAIL | SKIPPED |
|---|---:|---:|---:|---:|
| Ubuntu radius | 0 | 377 | 0 | 1 |
| Ubuntu adminapi | 0 | 328 | 0 | 0 |

Real generated-module integration: **22/22 PASS**, separately counted. The ordinary RADIUS package's opt-in fixture skip does not replace this live execution. Existing-deployment probes: **21/21 PASS**; its readiness response remains blocked.

Historical October 22 full Ubuntu suite: 1,400 PASS / 0 FAIL / 2 SKIPPED, PostgreSQL 14.24 matrix 152 PASS, Python security tests 33 PASS. These are preserved results, not a new full Ubuntu run. The changed package and consumer received fresh runtime coverage; unrelated packages were not repeated unnecessarily.

The matching FreeRADIUS 3.0.26 PostgreSQL package was downloaded and extracted only under `/home/bikram/aegisnas-pg-radius-20261023/`. Private PostgreSQL 14 libraries were used; the system package database and installed daemon were not altered. No reboot was requested or performed by this continuation.
