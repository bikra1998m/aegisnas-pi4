# NAS-0037 64-bit Accounting Counters And Gigawords

NAS-0037 makes accounting octet handling safe for long-lived sessions, ISP/BNG
traffic volumes, and enterprise AP/controller exports that use RFC 2866
gigawords.

## Problem

RADIUS accounting carries low 32-bit octets in `Acct-Input-Octets` and
`Acct-Output-Octets`. Large sessions use `Acct-Input-Gigawords` and
`Acct-Output-Gigawords` as the high 32-bit counters. Without normalizing the
low/high pair into one unsigned 64-bit total, session usage can wrap, shrink,
or be billed incorrectly.

## Supported Attributes

- `Acct-Input-Octets`
- `Acct-Input-Gigawords`
- `Acct-Output-Octets`
- `Acct-Output-Gigawords`

The same semantics are used by standard RADIUS accounting and by vendor
dictionary surfaces for Cisco, Juniper, Huawei, Cambium, and other NAS devices
that export RFC 2866 accounting counters.

## Runtime Behavior

- Local accounting records with counters larger than 32 bits are split into
  low octets plus gigawords for FreeRADIUS-compatible `radacct` rows.
- FreeRADIUS SQL rows containing low octets plus gigawords are reconciled into
  64-bit `sessions.bytes_in` and `sessions.bytes_out` values.
- `radius_accounting_events` stores normalized low octets, gigawords, decimal
  64-bit totals, rollover evidence, reset evidence, and overflow status.
- `radacct` stores `acctinputgigawords`, `acctoutputgigawords`,
  `aegis_input_octets_64`, `aegis_output_octets_64`,
  `aegis_counter_status`, reset counts, and the last counter event ID.
- If a later non-Start accounting event reports lower counters than the current
  session snapshot, AegisNAS records `reset_detected` evidence and keeps the
  larger accumulated session totals instead of silently reducing usage.
- If a gigaword value exceeds the supported 32-bit high-counter range, AegisNAS
  saturates the 64-bit total and exposes `overflow` evidence.

## Configuration

```yaml
radius:
  accounting_counters:
    enabled: true
    gigawords_enabled: true
    reset_detection_enabled: true
    max_counter_bits: 64
    overflow_policy: saturate
    retention_days: 365
```

Production readiness blocks when the counter engine is disabled, gigaword
support is disabled, reset detection is disabled, max counter width is not 64
bits, or overflow/error rows remain.

## API And Evidence

```text
GET /api/v1/system/accounting-counters
```

The response includes the effective policy, supported attributes, RFCs, vendor
scope, maximum observed 64-bit input/output totals, rollover count, reset count,
error count, and warnings. The same report appears in:

- `/api/v1/system/status` as `radius.accounting_counters`
- production readiness as `radius_accounting_counters`
- support bundles as `api/accounting-counters.json`
- Access Settings and Dashboard accounting panels

## Operations

Before production sign-off:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-counters | jq '.report.status, .report.summary'
```

After importing FreeRADIUS SQL rows or replaying accounting events, refresh the
counter report and confirm:

- `status` is `ready`
- `counter_error_rows` is `0`
- expected long sessions appear in `gigaword_rows` or `rollover_events`
- reset evidence is explainable by a NAS reboot, session restart, or controlled
  drill

## Release Boundary

Software implementation is complete when the schema, packet/SQL normalization,
API, UI, readiness checks, support bundle evidence, tests, docs, and CI target
pass. Real vendor packet captures, production Linux FreeRADIUS imports, HA
failover drills, performance benchmarks, and long-duration soak tests are
tracked in `nas-0037-release-certification-checklist.md`.
