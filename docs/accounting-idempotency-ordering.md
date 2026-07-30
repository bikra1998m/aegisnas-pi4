# Accounting Idempotency And Ordering

NAS-0036 adds a durable accounting event ledger in front of session and
FreeRADIUS SQL accounting updates.

## Problem

RADIUS accounting is delivered over UDP in many deployments. Access devices can
retry packets, send `Interim-Update` before `Start`, deliver a late `Stop`, or
replay records after a controller or proxy outage. A NAS/AAA platform must not
double count those packets, reopen closed sessions, or lose terminal usage.

## Implemented Software

The schema now includes `radius_accounting_events`.

Each accounting packet or reconciled `radacct` snapshot receives:

- deterministic `event_id`
- stable `acct_unique_id`
- normalized session key
- event and arrival timestamps
- status type: `Start`, `Interim-Update`, `Stop`, `Accounting-On`,
  `Accounting-Off`, or `Unknown`
- packet fingerprint and redacted JSON evidence
- apply status, ordering status, duplicate count, and replay timestamps

The apply engine:

- suppresses duplicate packets by `event_id`
- applies pending events in session/time/status order
- preserves the earliest known session start
- preserves the latest known activity
- merges late `Stop` records without reopening a closed session
- keeps counters monotonic and delegates gigaword/reset semantics to NAS-0037
- mirrors applied state into `radacct`
- supports bounded operator replay

## Configuration

```yaml
radius:
  accounting_ordering:
    enabled: true
    replay_enabled: true
    sequence_window_seconds: 300
    late_stop_window_seconds: 86400
    max_replay_batch: 1000
    duplicate_retention_days: 365
```

Lite nodes should use smaller replay batches and shorter retention. Enterprise
nodes can use larger replay batches and longer duplicate retention when
PostgreSQL is active.

## API

```text
GET  /api/v1/system/accounting-ordering
GET  /api/v1/system/accounting-ordering?status=pending&session_key=sess-1&limit=100
POST /api/v1/system/accounting-ordering/replay
```

Read access is available to read-only, guest, ops, and super admins. Replay is
limited to ops and super admins.

The same report appears in:

- `/api/v1/system/status` as `radius.accounting_ordering`
- `/api/v1/system/production-readiness` as `radius_accounting_ordering`
- support bundles as `api/accounting-ordering.json`

## FreeRADIUS Attributes

NAS-0036 normalizes accounting event identity and ordering for these standard
fields:

- `Acct-Session-Id`
- `Acct-Unique-Session-Id`
- `Acct-Status-Type`
- `Acct-Input-Octets`
- `Acct-Output-Octets`
- `Acct-Session-Time`
- `Acct-Terminate-Cause`
- `Event-Timestamp`
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

## Operator Checks

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-ordering | jq '.report.status, .report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"limit":1000}' \
  http://127.0.0.1:8083/api/v1/system/accounting-ordering/replay | jq '.status, .result'
```

Production readiness blocks when accounting ordering is disabled, replay is
disabled, the ledger table is unavailable, or stale/error events remain.

## Scope Boundary

NAS-0036 owns event identity, duplicate suppression, ordered apply, late Stop
merge, and bounded replay. Adjacent and later roadmap items own:

- NAS-0037 gigaword rollover and 64-bit counter invariants
- NAS-0038 IPv6, route, and delegated-prefix lifecycle accounting
- NAS-0039 multi-service and subscriber correlation
- NAS-0040 durable local ingest spool and crash replay
- NAS-0041 charging records, exports, and billing interfaces
