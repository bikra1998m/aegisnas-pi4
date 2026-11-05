# PostgreSQL and real API integration — 2026-10-26

**PASS: 220 SQLite and 220 PostgreSQL API checks.** The revised built API and
admin CLI ran against isolated databases. PostgreSQL 14 used a new private
cluster and dedicated `aegis_smoke_recovery` database on loopback. `fsync`,
`full_page_writes` and `synchronous_commit` were all ON. Initialization, startup,
settings capture, database creation, application migration/seed and shutdown
commands exited zero. The server's production durability settings were not
weakened. Local trust authentication is a fixture property, not production PKI.

The PostgreSQL run specifically asserts HTTP 409 from SQLite rollback-package
download and a rehearsal report with `ran=false`, `succeeded=false`, and an
explicit PostgreSQL unsupported explanation. A local SQLite file is no longer
misrepresented as a PostgreSQL recovery package. SQLite backup/API behavior,
authentication checks, support-bundle release state, OpenAPI discovery, built
UI serving and parameter-free system GET routes also passed. These are API
functional checks; GET availability does not prove every roadmap's enforcement.

The fixture performed actual migration and seed as part of startup. It did
not rerun the separate 156-case shared lifecycle/transaction matrix or 117-packet
SQL accounting fixture because their implementation inputs are unchanged.
Those earlier October 26 results remain historical execution evidence in the
[accounting report](2026-10-23-sql-accounting-readiness.md). No production database
was migrated, restored or reset. PostgreSQL encrypted backup/orchestration,
SQLite-to-PostgreSQL conversion, HA/outage/soak and full service acceptance remain
open NAS-0008 work.

| Sequential loopback release-status requests | Median ms | p95 ms | Max ms |
|---|---:|---:|---:|
| SQLite, 100 requests, concurrency 1 | 0.694 | 10.047 | 47.315 |
| PostgreSQL, 100 requests, concurrency 1 | 0.888 | 1.599 | 3.083 |

This endpoint reports missing release admission. Measurements include this VM's
current load and do not establish database throughput, NAS forwarding capacity,
maximum archive capacity, a latency SLO, or Raspberry Pi performance.
Raw results and retained cluster logs: `api-sqlite/`, `api-postgres/` and
`api-postgres-fixture/` under `.tmp/recovery-security-20261026/`.
