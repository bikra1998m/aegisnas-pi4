# NAS-0008 Release Certification Checklist

Engineering status: **Partial (reopened 2026-10-15; updated 2026-10-23)**.

October 26 recovery clarification: SQLite snapshot/download and local upgrade
rehearsal paths now explicitly reject PostgreSQL or report it as unsupported.
The earlier HTTP smoke successes did not certify PostgreSQL backup. Encrypted
recovery staging currently covers SQLite only; PostgreSQL coordinated backup,
rehearsal and activation remain open. See the
[recovery guide](authenticated-recovery-staging.md).

The latest accounting continuation adds generated PostgreSQL accounting/post-auth
queries and schema 103 revision guards. See the [implementation guide](postgresql-radius-accounting.md)
and [current execution report](reports/2026-10-23-sql-accounting-readiness.md).
Earlier schema-102 results below remain historical. Passing isolated query and
session checks does not close production module, durability or deployment gates.

Shared lifecycle fixtures now exercise real PostgreSQL: migrations through 102,
repeat seed, audit, transaction rollback, existing integer-width upgrade,
accounting/session/spool/identity/policy/vendor lifecycles and authentication
expiry. Portable Boolean, timestamp, aggregate, RETURNING and time-function
handling repairs preserve SQLite behavior. The PostgreSQL connection policy
enforces configured TLS and per-connection timeouts. SQLite file replication is
explicitly rejected for PostgreSQL before touching replication archives.

- [x] Run shared database lifecycle matrix on PostgreSQL 14.24 and 18.6 (152 test/subtests each; see exact source/toolchain epochs in reports).
- [x] Run fresh/repeated schema-102 migrations, repeat seed, audit reads, rollback and existing-integer upgrade on real PostgreSQL.
- [x] Exercise accounting, charging, session ownership, spool and authentication-expiry database workflows with populated fixtures.
- [x] Run isolated real API smoke tests including parameter-free system GET routes against SQLite and PostgreSQL.
- [ ] Complete service-write, FreeRADIUS SQL and external-device integration acceptance.
- [ ] Complete long-duration, outage, migration conversion, HA and production deployment certification below.

See [current PostgreSQL evidence](reports/2026-10-22-production-postgresql.md)
and [repeatable validation scope](postgresql-runtime-validation.md). Earlier
failures, harness corrections and toolchain-specific results remain separately
reported. An isolated fixture PASS is not production acceptance.

## External Certification / Deployment

- [ ] Provision supported PostgreSQL versions on Ubuntu production Linux.
- [ ] Validate `database.dsn_ref` through systemd environment and file-secret
      providers.
- [x] Run real PostgreSQL migrations with TLS `verify-full` in the isolated Ubuntu fixture, including wrong-root/hostname rejection (25 TLS/restore checks PASS). Production PKI remains pending.
- [x] Propagate DSN TLS policy into the generated FreeRADIUS libpq URI. Isolated Ubuntu FreeRADIUS 3.0.26/PostgreSQL 14 validation passed 22 checks, including real SCRAM/TLS SQL-backed RADIUS requests, wrong-root/hostname rejection and database outage/reconnect. The matching module package was extracted privately; the installed deployment was unchanged.
- [ ] Install and certify the SQL module in production. Generated PostgreSQL accounting/post-auth queries and packet-to-session reconciliation are now implemented; their current evidence and remaining limits are in the accounting report. The earlier 22-check diagnostic fixture alone did not cover these writes.
- [ ] Run old-version SQLite to new-version PostgreSQL migration rehearsal.
- [x] Rehearse PostgreSQL logical dump/restore in an isolated Ubuntu database: 181 table counts, schema 102 and audit fixture preserved. Production backup orchestration, encryption and retention remain pending.
- [ ] Validate managed PostgreSQL backup snapshots where used by the customer.
- [ ] Run active/standby appliance drills with PostgreSQL as shared data plane.
- [ ] Complete application-wide PostgreSQL outage and recovery tests. The isolated FreeRADIUS connection now has an executed outage/reconnect check; this does not cover the remaining services or HA.
- [ ] Run long-duration accounting/session soak tests.
- [ ] Run performance benchmarks for configured lite, branch, and enterprise
      pool settings.
- [ ] Run security review for DSN handling, TLS mode, support bundle redaction,
      and database role privileges.
- [ ] Capture customer acceptance evidence for production deployment.

## Release Evidence To Attach

- `/api/v1/system/database` output with DSN values absent.
- `/api/v1/system/production-readiness` output showing `database_data_plane`.
- PostgreSQL server version, TLS certificate chain, and `sslmode`.
- Migration logs and `database_backend_events` sample.
- FreeRADIUS startup logs with PostgreSQL SQL module loaded.
- Backup and restore transcript.
- HA/failover transcript.
- Soak and benchmark summary.
