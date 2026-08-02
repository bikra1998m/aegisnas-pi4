# Accounting Ingest Spool And Replay

NAS-0040 adds a durable local write-ahead queue in front of the accounting
event ledger. Local `Accounting-Request` records are persisted before the
ledger/session apply step, then replayed through the same idempotent accounting
pipeline used by SQL reconciliation and manual event replay.

## Why It Exists

RADIUS accounting is the operational record for sessions, traffic counters,
subscriber services, delegated prefixes, and billing evidence. If a database
apply, service restart, or failover happens while accounting packets are being
processed, the NAS must not silently lose those records.

The ingest spool provides:

- durable local persistence before ledger apply
- explicit backpressure when the queue is full
- retry with bounded exponential backoff
- poison evidence for checksum mismatches or exhausted attempts
- loss-SLO visibility for records waiting too long
- manual and background replay through existing idempotent ledger logic
- HA-safe claiming with owner and lock windows

## Data Model

Schema v45 adds:

- `radius_accounting_ingest_spool`
- `radius_accounting_ingest_spool_attempts`

The spool stores normalized accounting event payloads, deterministic record IDs,
checksums, status, retry timing, owner node, attempt counts, and terminal
timestamps. API and support-bundle output expose metadata and checksums, not raw
payload JSON.

Record states:

- `queued`
- `retrying`
- `applied`
- `poison`
- `expired`

Attempt results:

- `applied`
- `failed`
- `poison`

## Packet Flow

1. `ProcessAccounting` validates `Start`, `Interim-Update`, and `Stop`.
2. The packet is normalized into `db.AccountingEventRecord`.
3. If `radius.accounting_ingest_spool.enabled` is true, the event is written to
   `radius_accounting_ingest_spool`.
4. The event is applied through `db.IngestAccountingEvent` and
   `db.ApplyAccountingEventByID`.
5. The spool attempt is marked `applied`, `queued`, or `poison`.
6. Background replay workers claim due records and reapply them through the same
   ledger path.

Duplicate packets keep the same deterministic event identity. Already-applied
duplicates are sent back through the ledger so duplicate counters remain
visible without replaying session mutations.

## Configuration

```yaml
radius:
  accounting_ingest_spool:
    enabled: true
    replay_enabled: true
    max_queue_records: 50000
    max_attempts: 10
    initial_retry_seconds: 5
    max_retry_seconds: 300
    record_ttl_seconds: 604800
    replay_interval_seconds: 30
    batch_size: 500
    lock_seconds: 120
    applied_retention_seconds: 86400
    poison_retention_seconds: 2592000
    loss_slo_seconds: 300
```

Validation rejects invalid retry windows, queue limits, TTLs, lock windows,
batch sizes, and loss-SLO settings before the service starts.

## API

```text
GET /api/v1/system/accounting-ingest-spool
GET /api/v1/system/accounting-ingest-spool?status=queued&limit=100
GET /api/v1/system/accounting-ingest-spool?record_id=<record-id>
POST /api/v1/system/accounting-ingest-spool/replay
```

Read endpoints are available to read-only roles. Replay is limited to
`ops_admin` and `super_admin`.

The same status is embedded in:

- `/api/v1/system/status` as `radius.accounting_ingest_spool`
- production readiness as `radius_accounting_ingest_spool`
- support bundles as `api/accounting-ingest-spool.json`

## Operations

Check queue health:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-ingest-spool | jq '.report.status, .report.summary'
```

Replay due records:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch_size":500}' \
  http://127.0.0.1:8083/api/v1/system/accounting-ingest-spool/replay | jq '.status, .applied, .failed, .poisoned'
```

Investigate poison records:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/accounting-ingest-spool?status=poison&limit=100' | jq '.records'
```

Production readiness blocks when the ingest spool is disabled, replay is
disabled, the database is unavailable, or policy limits are invalid. It degrades
when poison, expired, loss-SLO breach, or high queue-utilization evidence is
present.

## Automation

Focused validation:

```bash
make test-radius-accounting-ingest-spool
```

The target covers config validation, schema migration, DB queue mechanics,
radius replay/apply behavior, admin API, OpenAPI, RBAC, production readiness,
and support bundle evidence.

## Software Completion

Software Implementation: 100% complete.

Engineering Implementation: 100% complete.

Ready for External Validation: Yes.

External certification, real hardware drills, FreeRADIUS Linux packet captures,
PostgreSQL HA validation, performance benchmarking, soak testing, security
audit, production deployment, and customer acceptance are tracked separately in
`nas-0040-release-certification-checklist.md`.
