# BNG QoS Service Flows

NAS-0087 implements the software lifecycle for broadband hierarchical QoS and
BNG service flows. It models subscriber/product/service-leg QoS intent,
profiles, parent-child hierarchy, aggregate controls, scheduler hints, DSCP
marking, vendor rate-attribute compilation, accounting correlation, CoA update
behavior, evidence history, support bundle capture, production readiness, and
admin UI operation.

## Scope

Software completion includes:

- `broadband.qos_service_flows` configuration and validation
- QoS profiles with min/rate/peak upload and download intent
- parent profile linkage for hierarchical service flows
- service-flow intent by product, service leg, subscriber, username, role, and tenant
- aggregate policies by tenant, product, subscriber group, or profile
- vendor pack compilation through the rate compiler
- RADIUS authorization/accounting binding evidence
- preview/apply APIs and RBAC
- durable event and effective flow tables
- runtime status, support bundle, OpenAPI, production readiness, UI, and tests

External certification remains outside software completion and is tracked in
`nas-0087-release-certification-checklist.md`.

## Configuration

The feature is configured under `broadband.qos_service_flows`.

Key fields:

- `enabled`: activates preview/apply governance
- `mode`: `monitor` or `enforce`
- `require_subscriber_state`: requires NAS-0083 subscriber state
- `require_commercial_catalog`: requires NAS-0084 commercial catalog
- `require_runtime_qos`: declares dependency on runtime QoS controls
- `require_rate_compiler`: requires vendor rate-attribute compilation
- `accounting_correlation_required`: requires accounting service correlation
- `coa_on_change`: requires dynamic authorization for active changes
- `aggregate_control_enabled`: requires at least one aggregate policy in enforce mode
- `profiles`: normalized QoS rates, schedulers, DSCP, hierarchy, and vendor packs
- `service_flows`: product/subscriber service-flow bindings
- `aggregate_policies`: tenant/product/profile aggregate limits

Use monitor mode until preview, support bundle, and release-certification
evidence agree with the target BNG environment.

## APIs

```text
GET  /api/v1/system/broadband-qos-service-flows
POST /api/v1/system/broadband-qos-service-flows/preview
POST /api/v1/system/broadband-qos-service-flows/apply
GET  /api/v1/system/broadband-qos-service-flows/history
```

Read-only, guest-admin, ops-admin, and super-admin users may read, preview, and
list history. Only ops-admin and super-admin users may apply.

## Persistence

NAS-0087 adds:

- `broadband_qos_service_flow_events`
- `broadband_qos_service_flows`

Events store preview/apply evidence, plan fingerprints, counts, compliance
status, and redacted reports. Effective service-flow rows store flow identity,
subscriber/product binding, rates, scheduler, compiled attributes, diagnostics,
plan fingerprint, install/withdraw timestamps, and status.

## Vendor Behavior

The normalized service-flow model compiles rate and QoS intent into vendor
families such as MikroTik, Huawei, WISPr, ZTE, Nokia/Alcatel-Lucent, Cisco BNG,
Juniper ERX/E-Series, Starent, and WiMAX where the configured vendor pack
supports equivalent attributes. The implementation records compiler diagnostics
instead of silently claiming support when a pack cannot represent the requested
intent.

## Operations

Preview first:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-qos-service-flows/preview \
  | jq '.report.status, .report.summary, .report.service_flows'
```

Apply after review:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-qos-service-flows/apply \
  | jq '.result.status, .event_id'
```

Collect evidence with:

- `/api/v1/system/broadband-qos-service-flows/history`
- support bundle files `api/broadband-qos-service-flows.json`
- support bundle files `api/broadband-qos-service-flows-history.json`
- production readiness key `broadband_qos_service_flows`

## Production Boundary

Engineering is complete when code, validation, tests, docs, API/UI, migration,
runtime status, and evidence are implemented and passing. Live scheduler
activation, BNG packet captures, hardware interoperability, HA failover, scale,
soak, security audit, and customer acceptance are release certification tasks.
