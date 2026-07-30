# FreeRADIUS SQL Accounting Reconciliation

NAS-0035 makes the product database own the FreeRADIUS-compatible `radacct` and
`radpostauth` tables and reconciles those rows into the AegisNAS `sessions`
model.

## Problem

FreeRADIUS SQL deployments expect standard accounting and post-auth tables.
Before NAS-0035, generated SQL configuration referenced the SQL module, while
the product schema did not create `radacct` or `radpostauth` and local
accounting packets only updated `sessions`.

That left two risks:

- FreeRADIUS SQL accounting could fail at runtime because the expected tables
  were absent.
- Accounting written by FreeRADIUS could drift from the product session view.

## Implemented Software

The schema now includes:

- `radacct`
- `radpostauth`
- `radius_sql_accounting_reconcile_events`

The RADIUS runtime now:

- mirrors local `Accounting-Start`, `Accounting-Interim-Update`, and
  `Accounting-Stop` records into `radacct`
- records broker authentication outcomes in `radpostauth` with passwords
  redacted
- reconciles pending or errored `radacct` rows into `sessions`
- marks reconciled rows with `aegis_session_id`, `aegis_reconcile_status`, and
  `aegis_reconciled_at`
- records every reconciliation run in
  `radius_sql_accounting_reconcile_events`
- prunes reconciled terminal accounting rows and post-auth rows according to
  retention policy

## Configuration

```yaml
radius:
  sql_accounting:
    enabled: true
    reconcile_enabled: true
    reconcile_interval_seconds: 60
    batch_size: 500
    stale_after_seconds: 300
    accounting_retention_days: 365
    postauth_retention_days: 30
```

Lite deployments should use shorter retention and smaller batches. Enterprise
deployments can increase retention and batch size when PostgreSQL is active.

## API

```text
GET  /api/v1/system/sql-accounting
GET  /api/v1/system/sql-accounting?status=pending&limit=100
POST /api/v1/system/sql-accounting/reconcile
```

Read access is available to read-only, guest, ops, and super admins. Manual
reconciliation is limited to ops and super admins.

The same report appears in:

- `/api/v1/system/status` as `radius.sql_accounting`
- `/api/v1/system/production-readiness` as `radius_sql_accounting`
- support bundles as `api/sql-accounting.json`

## FreeRADIUS Attributes

NAS-0035 covers the schema bridge for these standard accounting fields:

- `Acct-Session-Id`
- `Acct-Unique-Session-Id`
- `Acct-Status-Type`
- `Acct-Start-Time`
- `Acct-Update-Time`
- `Acct-Stop-Time`
- `Acct-Input-Octets`
- `Acct-Output-Octets`
- `Acct-Session-Time`
- `Acct-Terminate-Cause`
- `User-Name`
- `Calling-Station-Id`
- `Called-Station-Id`
- `NAS-IP-Address`
- `NAS-Port`
- `NAS-Port-Type`
- `Framed-IP-Address`
- `Framed-IPv6-Address`
- `Framed-IPv6-Prefix`
- `Delegated-IPv6-Prefix`
- `Class`

## Scope Boundary

NAS-0035 is the schema and reconciliation foundation. NAS-0036 now owns
duplicate, ordering, and late-event semantics through
`radius_accounting_events`. Later roadmap items own:

- NAS-0037 gigaword rollover and 64-bit counter invariants
- NAS-0038 IPv6, route, and delegated-prefix lifecycle accounting
- NAS-0039 multi-service and subscriber correlation
- NAS-0040 durable local ingest spool and replay
- NAS-0041 charging records, exports, and billing interfaces

## Operator Checks

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/sql-accounting | jq '.report.status, .report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch_size":500}' \
  http://127.0.0.1:8083/api/v1/system/sql-accounting/reconcile | jq '.status, .result'
```

Production readiness blocks when SQL accounting is disabled, reconciliation is
disabled, the database is unavailable, or stale/error rows remain.
