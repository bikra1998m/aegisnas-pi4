# PostgreSQL and deployed Ubuntu validation - 2026-11-05

Fresh deployed checks: **19 PASS / two FAIL out of 21**. The failures were
20-second authenticated readiness/system-status GET timeouts. Separate retries
with the same deadlines passed 2/2 in 1.614s and 2.868s. HTTP success did not imply
production readiness: the response is blocked, with five blockers, four warnings,
17 degraded checks and 68 passing checks.

Blocking keys: `radius_outbound_dac_client`, `radius_accounting_services`,
`identity_source_failover`, `eap_machine_user_correlation`, `secret_providers`.

PASS: eight services remained active with identical PIDs and activation timestamps
through the final post-work snapshot. Service health, authentication rejection,
authorized roles/database reads, FreeRADIUS configuration and an actual random
nonexistent-user PAP rejection were exercised. A health request during Go load
also returned HTTP 200. See exact checks in [results](2026-11-05-roadmap-results.json).
These tests cover the existing deployment at `7004511cfbea5f30d53db9b6ac768e059d7cfaf1`;
the current development candidate was not installed.

Fresh local PostgreSQL migration/accounting fixtures: SKIPPED because the local
suite had no isolated PostgreSQL test connection configured. Hosted PostgreSQL
14/18 and FreeRADIUS workflows are configured and must report their actual results
after publication. No existing production database is repurposed as a fixture.

Historical evidence remains valid for its dated inputs, not automatically for the
new dependency: [SQL accounting](2026-10-23-sql-accounting-postgresql.md) records
PostgreSQL 14/18 compatibility/lifecycle checks and 117 actual RADIUS packet
assertions. [Recovery integration](2026-10-26-recovery-postgresql.md) records 220
actual API checks on each of SQLite and isolated PostgreSQL. Schema 103 guards
accounting snapshots and supports Start/Interim/Stop/NAS On/Off/post-auth paths.
Snapshot coalescing is not lossless billing. HA/outage/durability/soak acceptance,
coordinated PostgreSQL recovery and production service completion remain open.

No reboot, manual service restart, production deployment, firewall change or
database replacement occurred. Observed request timings are the only new live
performance measurements; production-scale throughput, Pi hardware and telecom
device enforcement were NOT TESTED. NAS-0008 and NAS-0092..0097 remain Partial.
