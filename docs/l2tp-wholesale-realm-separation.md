# L2TP Wholesale Realm Separation

NAS-0088 implements the software lifecycle for L2TP tunnel selection and
wholesale realm separation. It models partner realms, LAC/LNS tunnel profiles,
auth and accounting proxy routes, tenant isolation, realm stripping, failover
policy, CoA recovery, evidence history, support bundle capture, production
readiness, and admin UI operation.

## Scope

Software completion includes:

- `broadband.l2tp_wholesale` configuration and validation
- wholesale realm bindings by realm, tenant, partner, product, address pool, QoS
  profile, proxy route, and accounting route
- L2TP tunnel profile metadata for LAC/LNS mode, peer endpoint, tunnel group,
  session limits, authentication methods, encryption requirement, and secret refs
- failover policies with primary and backup tunnel references, accounting replay,
  hold-down behavior, and CoA action
- compiled RADIUS evidence for standards attributes and major vendor AVPair
  families
- RADIUS authorization/accounting binding evidence
- preview/apply APIs and RBAC
- durable event and effective realm-binding tables
- runtime status, support bundle, OpenAPI, production readiness, UI, and tests

External certification remains outside software completion and is tracked in
`nas-0088-release-certification-checklist.md`.

## Configuration

The feature is configured under `broadband.l2tp_wholesale`.

Key fields:

- `enabled`: activates preview/apply governance
- `mode`: `monitor` or `enforce`
- `require_pppoe`: requires PPPoE access lifecycle
- `require_subscriber_state`: requires wholesale subscriber state
- `require_proxy_routes`: requires RADIUS upstream proxy routes
- `require_accounting_delegation`: requires SQL accounting and service
  correlation
- `require_tunnel_failover`: requires at least one failover policy in enforce
  mode
- `realm_isolation_required`: keeps wholesale tenant/partner routing explicit
- `strip_customer_realm`: strips the customer realm where upstream routes require
  local usernames
- `accounting_delegation_enabled`: records Start/Interim/Stop delegation
  bindings
- `coa_on_failover`: requires dynamic authorization for tunnel recovery
- `selection_policy`: `explicit`, `realm`, `tenant`, `load_balance`, or
  `failover`
- `realms`: partner realm bindings and route/accounting delegation
- `tunnel_profiles`: LAC/LNS endpoint and tunnel-group metadata
- `failover_policies`: primary/backup tunnel recovery rules

Use monitor mode until preview, support bundle, packet capture, and partner LNS
evidence agree with the target wholesale environment.

## APIs

```text
GET  /api/v1/system/broadband-l2tp-wholesale
POST /api/v1/system/broadband-l2tp-wholesale/preview
POST /api/v1/system/broadband-l2tp-wholesale/apply
GET  /api/v1/system/broadband-l2tp-wholesale/history
```

Read-only, guest-admin, ops-admin, and super-admin users may read, preview, and
list history. Only ops-admin and super-admin users may apply.

## Persistence

NAS-0088 adds:

- `broadband_l2tp_wholesale_events`
- `broadband_l2tp_wholesale_bindings`

Events store preview/apply evidence, plan fingerprints, counts, compliance
status, and redacted reports. Effective realm-binding rows store realm identity,
tenant, partner, tunnel profile, proxy route, accounting route, compiled
attributes, failover policy, plan fingerprint, install/withdraw timestamps, and
status.

## Vendor Behavior

The normalized model compiles standards-based tunnel attributes such as
`Tunnel-Type=L2TP`, `Tunnel-Medium-Type`, `Tunnel-Server-Endpoint`,
`Tunnel-Client-Endpoint`, `Tunnel-Private-Group-ID`, `Class`, and `Proxy-State`.
Vendor pack evidence adds AVPair bindings for Cisco, Juniper/ERX,
Nokia/Alcatel-Lucent SR OS, Huawei, and H3C where configured. Unsupported live
tunnel activation remains a release certification item instead of a silent
software claim.

## Operations

Preview first:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-l2tp-wholesale/preview \
  | jq '.report.status, .report.summary, .report.realms'
```

Apply after review:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-l2tp-wholesale/apply \
  | jq '.result.status, .event_id'
```

Collect evidence with:

- `/api/v1/system/broadband-l2tp-wholesale/history`
- support bundle files `api/broadband-l2tp-wholesale.json`
- support bundle files `api/broadband-l2tp-wholesale-history.json`
- production readiness key `broadband_l2tp_wholesale`

## Production Boundary

Engineering is complete when code, validation, tests, docs, API/UI, migration,
runtime status, and evidence are implemented and passing. Live LAC/LNS tunnel
establishment, partner LNS packet captures, hardware interoperability, HA
failover, accounting replay, scale, soak, security audit, production deployment,
and customer acceptance are release certification tasks.
