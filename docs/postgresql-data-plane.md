# PostgreSQL Data Plane

NAS-0008 adds PostgreSQL as the enterprise production data plane while keeping
SQLite as the default lite/lab backend.

## What It Solves

SQLite is simple and reliable for a single low-spec appliance, but it is not the
right shared state store for enterprise AAA, long retention, HA, or later
multi-node ownership features. PostgreSQL provides a production database target
for sessions, accounting history, admin state, vendor evidence, and future
replicated services.

## Configuration

SQLite remains the default:

```yaml
database:
  backend: sqlite
  path: /var/lib/aegisnas/data.db
```

Enterprise deployments should use a secret reference for the PostgreSQL DSN:

```yaml
database:
  backend: postgres
  dsn_ref: "env:AEGIS_SECRET_POSTGRES_DSN"
  sslmode: verify-full
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime_seconds: 1800
  conn_max_idle_time_seconds: 300
  connect_timeout_seconds: 10
  statement_timeout_milliseconds: 30000
  migration_lock_timeout_seconds: 30
  production_require_postgresql: true
  production_require_tls: true
```

The DSN should use a `postgres://` or `postgresql://` URL:

```text
postgres://aegisnas:REDACTED@postgres.example.net:5432/aegisnas?sslmode=verify-full
```

Inline `database.dsn` is blocked by default. It is only available for controlled
lab use with `database.allow_inline_postgresql_dsn: true`.

## Runtime Behavior

For an isolated existing-data rehearsal, use
[SQLite-to-PostgreSQL conversion](sqlite-postgresql-conversion.md). The CLI snapshots
and upgrades a copy, imports into a new private schema, and verifies data and IDs.
It does not switch the active data plane or complete production deployment acceptance.

The runtime opens SQLite with the existing `modernc.org/sqlite` driver and
PostgreSQL with the internal `aegis-pgx` wrapper around pgx. The wrapper keeps
existing application SQL compatible by translating:

- `?` placeholders to `$1`, `$2`, ...
- SQLite `INSERT OR IGNORE` to PostgreSQL `ON CONFLICT DO NOTHING`
- common `datetime('now', '-N unit')` expressions to PostgreSQL intervals

The runtime compatibility work also handles nested datetime expressions, native
Boolean parameters, nullable timestamps, generated revision IDs, and PostgreSQL
14 subquery aliases. Returned native timestamps use UTC. Connection configuration
overrides conflicting DSN TLS settings, and every pooled connection receives the
configured statement timeout and UTC server timezone.

Schema v102 preserves SQLite's signed 64-bit integer range on PostgreSQL. Fresh
schemas use `BIGINT`; the upgrade widens existing `INTEGER` columns only in tables
declared by AegisNAS migrations in the current schema. It preserves their values
and leaves unrelated tables alone. **This upgrade can take table locks and rewrite
tables.** Rehearse it on a restored copy with representative data and arrange a
maintenance window before applying it to an existing production database. It is
not a tested automatic downgrade path.

Schema migrations are emitted per dialect. PostgreSQL migrations convert
SQLite-only DDL such as `AUTOINCREMENT`, `DATETIME`, boolean integer defaults,
and partial boolean indexes into PostgreSQL-safe SQL.

Schema v17 adds `database_backend_events`, which records backend lifecycle
evidence without storing credentials.

## APIs And Evidence

Use:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8083/api/v1/system/database | jq .
```

The response reports backend, schema target, pool settings, TLS posture, DSN
reference status, DSN fingerprint, and HA readiness. It never returns the DSN or
database password.

Production readiness includes `database_data_plane`. SQLite is degraded for
enterprise production. PostgreSQL with `dsn_ref` and TLS is the intended pass
state.

Support bundles include:

- `api/database.json`
- `system/database-backend.txt`
- redacted `database.dsn`
- visible `database.dsn_ref`

## FreeRADIUS SQL

When `database.backend: postgres` is active, generated FreeRADIUS SQL config
uses:

```text
dialect = "postgresql"
driver = "rlm_sql_postgresql"
```

The DSN must be a `postgres://` or `postgresql://` URL. Generation applies the
same configured TLS policy as the Go application, preserves certificate paths,
and passes an encoded libpq URI through `radius_db`. Configured `sslmode`
overrides a weaker value in the DSN. UTC and statement timeout use libpq `options`;
connection timeout is positive and defaults to ten seconds if not specified.
Ambiguous duplicate parameters, malformed queries and unsupported connection
parameters fail generation instead of being silently discarded. Keyword DSNs
remain unsupported for FreeRADIUS generation.

Generated files are restricted to owner read/write and group read (0640),
preserving existing file ownership/group. Ensure the service has access through
the configured group. Debug output can reveal the connection URI; automatic
validation suppresses that output in returned errors. Operator debug logs must
remain private. See [the isolated SQL/TLS fixture](postgresql-runtime-validation.md).
Production accounting/post-auth query generation remains unfinished; successful
TLS connectivity alone is not approval to switch an appliance to PostgreSQL.

## Operational Notes

SQLite file backup and restore commands remain valid for SQLite deployments.
PostgreSQL deployments must use PostgreSQL logical or managed backups and export
the AegisNAS config separately.

File-based appliance replication now rejects PostgreSQL configurations before
reading or activating a SQLite snapshot. The replication-package API returns
HTTP 409 for that unsupported operation. This guard does not implement
PostgreSQL replication or failover.

See [runtime verification and recovery boundaries](postgresql-runtime-validation.md)
for the shared database matrix and the isolated TLS/restore rehearsal. NAS-0008
remains **Partial** until its remaining software and acceptance requirements are
met; successful migration and read-API tests alone do not certify every live
integration.

Full PostgreSQL HA, consensus, multi-writer ownership, and rolling mixed-version
schema quorum are later roadmap items. NAS-0008 provides the software data-plane
foundation and readiness evidence.
