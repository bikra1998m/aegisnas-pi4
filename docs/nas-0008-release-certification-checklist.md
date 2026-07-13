# NAS-0008 Release Certification Checklist

NAS-0008 software implementation is complete when code, config, APIs, tests, CI,
and documentation are complete. The following activities require external
systems, production Linux, or customer environments and do not block engineering
closure.

## External Certification / Deployment

- [ ] Provision supported PostgreSQL versions on Ubuntu production Linux.
- [ ] Validate `database.dsn_ref` through systemd environment and file-secret
      providers.
- [ ] Run migrations against a real PostgreSQL server with TLS `verify-full`.
- [ ] Confirm FreeRADIUS `rlm_sql_postgresql` package availability and generated
      SQL module startup.
- [ ] Run old-version SQLite to new-version PostgreSQL migration rehearsal.
- [ ] Validate PostgreSQL logical backup and restore runbooks.
- [ ] Validate managed PostgreSQL backup snapshots where used by the customer.
- [ ] Run active/standby appliance drills with PostgreSQL as shared data plane.
- [ ] Run controlled PostgreSQL outage and recovery tests.
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
