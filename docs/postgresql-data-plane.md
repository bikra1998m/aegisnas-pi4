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

The runtime opens SQLite with the existing `modernc.org/sqlite` driver and
PostgreSQL with the internal `aegis-pgx` wrapper around pgx. The wrapper keeps
existing application SQL compatible by translating:

- `?` placeholders to `$1`, `$2`, ...
- SQLite `INSERT OR IGNORE` to PostgreSQL `ON CONFLICT DO NOTHING`
- common `datetime('now', '-N unit')` expressions to PostgreSQL intervals

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

The DSN must be a URL so host, port, login, password, and database can be
rendered into FreeRADIUS syntax. Apply RADIUS config after changing database
backend settings.

## Operational Notes

SQLite file backup and restore commands remain valid for SQLite deployments.
PostgreSQL deployments must use PostgreSQL logical or managed backups and export
the AegisNAS config separately.

Full PostgreSQL HA, consensus, multi-writer ownership, and rolling mixed-version
schema quorum are later roadmap items. NAS-0008 provides the software data-plane
foundation and readiness evidence.
