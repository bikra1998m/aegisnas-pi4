# NAS-0041 Charging Records, Rating, Retention, And Export Integrity

NAS-0041 turns normalized RADIUS accounting events into durable charging data
records (CDRs), rates closed records, retains billing evidence, and exports
hash-verified batches for external billing or mediation systems.

## Problem

Enterprise Wi-Fi, VPN, BNG/BRAS, hotspot, voice, and mobile-core devices all
emit accounting records, but billing systems need stable CDRs rather than raw
packet rows. A production NAS/AAA platform must survive duplicate packets,
late Stop records, gigaword rollover, service-leg correlation, and local crash
replay without double-charging or losing billable usage.

## Vendor And Standards Scope

This feature covers the charging foundation used by vendors represented in
FreeRADIUS dictionaries for:

- ISP and broadband NAS devices from Cisco, Juniper, Huawei, Nokia/Alcatel,
  Ericsson, MikroTik, Cambium, and related BRAS/BNG families
- mobile and packet-core workflows from 3GPP, 3GPP2, Starent/Cisco, and
  Ericsson dictionaries
- voice, SBC, VPN, and hotspot products that expose usage through standard
  RADIUS accounting and vendor-specific session metadata

Primary protocol basis:

- RFC 2866 RADIUS Accounting
- RFC 2865 shared session identity attributes used with accounting state
- RFC 5080 duplicate and retransmission behavior guidance
- 3GPP TS 32.240 style charging-record lifecycle for later mobile mediation
  integration

Core attributes:

- `Acct-Status-Type`
- `Acct-Session-Id`
- `Acct-Unique-Session-Id`
- `Acct-Multi-Session-Id`
- `Acct-Input-Octets`
- `Acct-Input-Gigawords`
- `Acct-Output-Octets`
- `Acct-Output-Gigawords`
- `Acct-Session-Time`
- `Service-Type`
- `Framed-Protocol`
- `Class`
- normalized AegisNAS service, bearer, call, roaming, route, and counter fields
  produced by NAS-0036 through NAS-0040

## Runtime Behavior

- Local accounting packets and FreeRADIUS SQL rows enter
  `radius_accounting_events`.
- Applied events project one CDR per normalized session and service leg into
  `radius_accounting_charging_records`.
- Start and Interim-Update records keep CDRs open. Stop and Accounting-Off
  records close them.
- Late corrections return exported CDRs to pending export and unrated state so
  corrected usage is exported again instead of silently diverging.
- Identity values are stored as hashes. Raw usernames or station IDs are not
  emitted in charging exports.
- Rating is deterministic and uses configured micro-unit rates per input GiB,
  output GiB, session hour, minimum charge, plan, and currency.
- Export batches support JSON Lines, JSON, and CSV.
- Each exported payload has a payload SHA-256 and a manifest SHA-256. The
  manifest links to the previous manifest hash to support tamper-evident
  export chains.
- Production readiness blocks when charging, rating, or export is disabled and
  degrades when rating or integrity errors are present.

## Database Model

- `radius_accounting_charging_records`: durable CDR state, normalized session
  and service keys, hashed identities, NAS identity, 64-bit counters, plan,
  currency, rating state, export state, lifecycle timestamps, and integrity
  hash.
- `radius_accounting_charging_exports`: immutable export batch metadata,
  payload bytes, payload hash, manifest hash, previous manifest hash, record
  count, amount, creator, and status.
- `radius_accounting_charging_export_records`: export membership table linking
  each CDR to the export batch and preserving the CDR integrity hash at export
  time.

Schema migration v46 creates the tables and indexes. Startup schema repair also
ensures the charging schema exists on existing databases.

## Configuration

```yaml
radius:
  accounting_charging:
    enabled: true
    rating_enabled: true
    export_enabled: true
    reconcile_interval_seconds: 300
    batch_size: 1000
    max_export_records: 5000
    export_format: jsonl
    default_plan: standard
    currency: USD
    input_micros_per_gib: 0
    output_micros_per_gib: 0
    session_micros_per_hour: 0
    minimum_charge_micros: 0
    open_retention_days: 90
    closed_retention_days: 2555
    export_retention_days: 2555
    integrity_sample_limit: 500
```

Lite deployments use smaller batches and shorter retention. Enterprise
deployments keep longer CDR/export evidence and a larger integrity sample.

## API And Evidence

```text
GET /api/v1/system/accounting-charging
GET /api/v1/system/accounting-charging?status=closed&export_status=pending&limit=100
POST /api/v1/system/accounting-charging/reconcile
POST /api/v1/system/accounting-charging/export
GET /api/v1/system/accounting-charging/export/download?export_id=<export-id>
```

Read endpoints are available to read-only and higher roles. Reconcile and
export actions require `ops_admin` or `super_admin`.

The same evidence appears in:

- `/api/v1/system/status` as `radius.accounting_charging`
- production readiness as `radius_accounting_charging`
- support bundles as `api/accounting-charging.json`
- Access Settings charging controls
- Dashboard accounting health

## Operations

Check status:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-charging | jq '.report.status, .report.summary'
```

Run a bounded reconcile and rating pass:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch_size":1000}' \
  http://127.0.0.1:8083/api/v1/system/accounting-charging/reconcile | jq '.status, .result, .summary'
```

Export pending closed/rated CDRs:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format":"jsonl","limit":5000}' \
  http://127.0.0.1:8083/api/v1/system/accounting-charging/export | jq '.export_id, .record_count, .payload_sha256, .manifest_sha256'
```

Download an export payload:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/accounting-charging/export/download?export_id=<export-id>' \
  -o aegisnas-cdr-export.jsonl
```

## Security And Privacy

- Export APIs are RBAC protected and audited.
- CDR exports omit raw user and station identities.
- Payload and manifest SHA-256 values provide tamper evidence.
- Support bundles include summary evidence and recent metadata, not raw
  accounting payloads.
- Rating config is validated before service startup or settings save.

## High Availability

The database owns CDR state, export metadata, and integrity hashes. Active and
standby nodes can rebuild reports from the same PostgreSQL-backed state. Replay
and reconcile operations are bounded and idempotent, so failover can rerun them
without duplicating exported CDR membership.

## Testing

Automated coverage includes:

- migration and schema repair
- CDR projection from Start, Interim-Update, Stop, and SQL-applied events
- deterministic rating from counters and session time
- late correction handling after export
- JSON Lines, JSON, and CSV export generation
- payload and manifest SHA-256 integrity
- tamper detection
- admin API, RBAC, OpenAPI, support bundle, and readiness checks
- Access Settings and Dashboard build coverage

Run the focused target:

```bash
make test-radius-accounting-charging
```

## Release Boundary

Software implementation is complete when schema, projection, rating, export,
retention, integrity verification, API, UI, readiness checks, support bundle
evidence, tests, docs, and CI target pass.

External billing mediation validation, real device packet captures, production
Linux FreeRADIUS import tests, HA drills, performance benchmarks, soak tests,
security audit, customer acceptance, and any compliance evidence are tracked in
`nas-0041-release-certification-checklist.md` and do not block engineering
closure.
