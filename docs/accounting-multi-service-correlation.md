# NAS-0039 Multi-Service Accounting Correlation

NAS-0039 correlates accounting records that belong to the same subscriber,
device, call, bearer, VPN, or reauthorization workflow. It turns isolated
RADIUS accounting rows into durable parent/child service-leg evidence.

## Problem

Enterprise and carrier NAS devices often create more than one accounting stream
for one user-visible session. A BNG can account PPP access, data service, and
subscriber services separately. A mobile gateway can account bearer legs and
APN service flows. Voice and SBC platforms can account call legs. VPN gateways
can account tunnel and reauthorization events independently.

Without a correlation model, operations teams cannot answer which service leg
belongs to which subscriber, which child record closed a parent session, or
whether two systems are claiming the same accounting leg.

## Supported Attributes

- `Acct-Multi-Session-Id`
- `Acct-Link-Count`
- `Service-Type`
- `Framed-Protocol`
- `Class`
- AegisNAS normalized parent, service, bearer, call, and roaming fields mirrored
  into `radacct`
- Vendor-specific call, bearer, APN, service, and accounting-class hints when
  they are present in Class metadata or normalized payloads

The feature covers standard RADIUS accounting semantics used by Juniper ERX,
Nokia SR, Huawei, Starent/Cisco ASR, Ericsson, BroadSoft, Acme Packet, Cisco
voice/VPN products, BNG/BRAS platforms, mobile packet-core integrations, and
other vendors that expose multi-service state through FreeRADIUS dictionaries.

## Runtime Behavior

- Local accounting packets and FreeRADIUS SQL `radacct` rows normalize the same
  service-correlation fields before they are applied.
- `Acct-Multi-Session-Id` becomes the default parent session when no explicit
  parent key is present.
- `Acct-Link-Count` is preserved for multi-link and parent/child accounting
  evidence.
- `Class` can carry key/value or JSON metadata such as `service_key`,
  `parent_session_key`, `service_leg_id`, `bearer_id`, `call_id`,
  `roaming_id`, and `accounting_class`.
- `radius_accounting_events` stores normalized parent, service, bearer, call,
  roaming, and correlation status fields beside duplicate/order/counter/IP
  evidence.
- `radacct` stores FreeRADIUS-compatible multi-session fields plus AegisNAS
  normalized `aegis_parent_session_id`, `aegis_service_key`,
  `aegis_service_category`, `aegis_service_leg_id`, bearer/call/roaming IDs,
  correlation ID/status/error, and the last correlation event ID.
- `radius_accounting_service_correlations` stores the durable service-leg
  timeline, hashed identities, counter snapshots, first/last event IDs,
  active/closed/conflict state, and subscriber service-chain linkage.
- When a correlation matches an active `subscriber_service_accounting` row,
  counters and Start/Interim/Stop status are mirrored into that service row.
- If one child session is claimed by another active parent correlation,
  AegisNAS records a conflict instead of silently overwriting ownership.

## Configuration

```yaml
radius:
  accounting_services:
    enabled: true
    correlate_subscriber_chains: true
    derive_from_class: true
    derive_from_acct_multi_session_id: true
    retain_unmatched: true
    retention_days: 365
    max_recent_services: 25
```

Production readiness blocks when the engine is disabled or when subscriber
chain, Class, or Acct-Multi-Session-Id correlation sources are disabled.
Conflict rows degrade readiness and should be investigated before production
claims.

## API And Evidence

```text
GET /api/v1/system/accounting-services
GET /api/v1/system/accounting-services?status=conflict&limit=100
GET /api/v1/system/accounting-services?parent_session_key=sess-1&limit=100
```

The response includes effective policy, supported attributes, RFCs, vendor
scope, service categories, active/closed/conflict counts, subscriber service
links, Acct-Multi-Session rows, bearer and call-leg counts, recent correlation
rows, and warnings. The same report appears in:

- `/api/v1/system/status` as `radius.accounting_services`
- production readiness as `radius_accounting_services`
- support bundles as `api/accounting-services.json`
- Access Settings and Dashboard accounting panels

## Operations

Before production sign-off:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-services | jq '.report.status, .report.summary'
```

After importing FreeRADIUS SQL rows, replaying accounting events, activating
subscriber service chains, or testing BNG/mobile/voice accounting, confirm:

- `status` is `ready`
- `conflict_correlations` is `0`
- expected parent sessions appear in `parent_sessions`
- expected service legs appear in `data_services`, `voice_services`,
  `bearer_services`, `vpn_services`, or `reauth_services`
- subscriber service-chain tests increase `linked_subscriber_services`
- Stop and Accounting-Off tests close active service-leg rows

## Release Boundary

Software implementation is complete when schema, packet/SQL normalization,
subscriber service linkage, API, UI, readiness checks, support bundle evidence,
tests, docs, and CI target pass. Real BNG/BRAS/mobile/voice/VPN packet captures,
production Linux FreeRADIUS imports, HA failover drills, performance benchmarks,
long-duration soak tests, security review, and customer acceptance are tracked
in `nas-0039-release-certification-checklist.md`.
