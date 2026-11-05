# PostgreSQL integration report

| Execution | Status | PASS | FAIL | SKIPPED |
|---|---|---:|---:|---:|
| Windows PostgreSQL 18.6, Go 1.26.10 | PASS | 152 | 0 | 0 |
| Ubuntu PostgreSQL 14.24, Go 1.26.10 | PASS | 152 | 0 | 0 |
| Windows PostgreSQL 18.6, Go 1.26.9 | PASS | 152 | 0 | 0 |
| Ubuntu PostgreSQL 14.24, Go 1.26.9 | PASS | 152 | 0 | 0 |
| Ubuntu PostgreSQL timeout attempt | FAIL | 145 | 2 | 0 |

Each shared matrix covers populated accounting, charging, spool, session, guest/voucher, identity, authentication-expiry, policy and vendor persistence lifecycles. Migration coverage includes schema 102, repeat seed, audit, rollback, per-connection policy and existing integer-width upgrade. Test schemas are uniquely owned; the deployed database is not the target. SQLite-specific migration/seed/vendor fixtures run in the ordinary suite instead.

Latest isolated TLS/logical-restore rehearsal: **PASS**, 25 PASS and 0 FAIL checks. It uses a fixture CA, actual application `verify-full`, untrusted-root and hostname rejection, negotiated TLS, pg_dump/pg_restore into a new empty fixture database, all-table counts, schema 102 and an audit fixture. Test certificates are not production trust or release signatures. Dumps and private keys remain outside Git.

The first attempt failed in libpq's hostname comparison while the application IP-SAN test passed. The next used `localhost`, negotiated TLS 1.3 and completed dump/restore, but an unordered UNION count comparison failed. Recorded counts were identical when matched by table; the corrected harness sorts them and the final outcome above comes from its actual execution. Both failures remain preserved.

NOT TESTED/BLOCKED: systemd/file-secret production integration; real FreeRADIUS PostgreSQL SQL module/packet path (freeradius-postgresql is not installed on the VM) and its missing TLS propagation; old SQLite data conversion; managed encrypted snapshots; controlled database outage/reconnect; PostgreSQL appliance HA; long soak and representative pool benchmarks. NAS-0008 remains Partial.

Raw evidence: `pg-matrix-patched/`, `patched-vm4/postgres-*`, `patched-vm4/tls-*`, `vm-serial-tls-*`, `vm-tls-retry-*`. See [validation guide](../postgresql-runtime-validation.md).
