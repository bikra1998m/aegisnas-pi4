# BNG Service Activation, Route Lifecycle, And Multicast

NAS-0090 implements the software lifecycle for broadband service activation,
subscriber route publish and withdraw governance, and multicast entitlement.
It ties subscriber state, commercial products, address leases, QoS service
flows, DHCP security, dynamic route export, accounting, and dynamic
authorization into one auditable preview/apply workflow.

## Scope

Software completion includes:

- `broadband.service_activation` configuration and validation
- dependency checks for subscriber state, commercial catalog, address leases,
  QoS service flows, DHCP security, route export, SQL accounting, accounting
  services, and dynamic authorization
- service activation transactions for product, subscriber, tenant, service
  chain, route policy, multicast profile, address pool, QoS profile, and
  accounting class
- route policy modeling for VRF, protocol, IPv4 and IPv6 prefixes, next hop,
  route target, metric, preference, withdrawal, aggregation, and vendor packs
- multicast entitlement modeling for IGMP, MLD, group addresses, sources,
  VLAN, VRF, querier interface, and per-subscriber entitlement
- transactional apply and rollback intent with durable history
- compiled standards and vendor evidence for `Framed-Route`,
  `Framed-IPv6-Route`, `Class`, `Filter-Id`, `Framed-Pool`,
  `Cisco-AVPair`, `Juniper-AV-Pair`, `ERX-Service-Activate`,
  `ERX-Update-Service`, `Huawei-AVpair`, `H3C-Av-Pair`,
  `Nokia-Service-Name`, `Nokia-AVPair`, and `ZTE-AVPair`
- preview/apply APIs and RBAC
- durable event and effective transaction tables
- runtime status, support bundle, OpenAPI, production readiness, UI, CI, and
  automated tests

External certification remains outside software completion and is tracked in
`nas-0090-release-certification-checklist.md`.

## Configuration

The feature is configured under `broadband.service_activation`.

Key fields:

- `enabled`: activates preview/apply governance
- `mode`: `monitor` or `enforce`
- `require_subscriber_state`: requires subscriber lifecycle state
- `require_commercial_catalog`: requires active product and subscription model
- `require_address_leases`: requires durable address lease ownership
- `require_qos_service_flows`: requires BNG QoS service-flow governance
- `require_dhcp_security`: requires DHCP relay/snooping/source-guard evidence
- `require_route_export`: requires dynamic route export readiness
- `require_accounting`: requires SQL accounting and service correlation
- `require_dynamic_auth`: requires CoA/Disconnect for update and rollback
- `transactional_apply`: records service activation as one auditable operation
- `rollback_on_failure`: requires rollback intent before enforcement
- `route_publish_enabled`: compiles route publish and withdraw evidence
- `multicast_enabled`: compiles multicast entitlement evidence
- `services`: product/subscriber activation transactions
- `route_policies`: route ownership and withdrawal intent
- `multicast_profiles`: group and source entitlement intent
- `activation_policies`: rollback, route, multicast, accounting, and failure
  behavior

Use monitor mode until preview output, support bundle evidence, route policy,
multicast entitlement, and BNG behavior agree with the target network.

## APIs

```text
GET  /api/v1/system/broadband-service-activation
POST /api/v1/system/broadband-service-activation/preview
POST /api/v1/system/broadband-service-activation/apply
GET  /api/v1/system/broadband-service-activation/history
```

Read-only, guest-admin, ops-admin, and super-admin users may read, preview, and
list history. Only ops-admin and super-admin users may apply.

## Persistence

NAS-0090 adds:

- `broadband_service_activation_events`
- `broadband_service_activation_transactions`

Events store preview/apply evidence, plan fingerprints, mode, service, route,
multicast, activation-policy, compliance, warning, blocker, external
requirement, and compiled attribute counts. Effective transaction rows store
transaction key, service name, product, subscriber, username, tenant, service
chain, route policy, multicast profile, address pool, QoS profile, accounting
class, vendor packs, compiled route/multicast/RADIUS attributes, rollback
requirement, source event, plan fingerprint, install/withdraw timestamps, and
status.

## Vendor Behavior

The normalized model compiles standards evidence for subscriber route and
service authorization. Vendor pack evidence adds:

- `Cisco-AVPair` for Cisco BNG subscriber service, route policy, and multicast
  profile evidence
- `Juniper-AV-Pair` and ERX VSAs for Juniper/ERX subscriber service
  activation, service update, virtual router, and route tag evidence
- `Huawei-AVpair` for Huawei BRAS/BNG subscriber service, route policy, and
  IGMP profile evidence
- `H3C-Av-Pair` for H3C service, route, and IGMP/MLD evidence
- `Nokia-Service-Name` and `Nokia-AVPair` for Nokia/SR OS service activation,
  route policy, and multicast profile evidence
- `ZTE-AVPair` for ZTE BNG service, route, and multicast evidence
- `AegisNAS-Subscriber-Product` and `AegisNAS-Multicast-Group` for
  product-neutral service and multicast correlation

Live BNG route convergence, route withdrawal, multicast forwarding, and
vendor CLI/API state remain release certification items instead of silent
software claims.

## Operations

Preview first:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-service-activation/preview \
  | jq '.report.status, .report.summary, .report.services, .report.route_policies'
```

Apply after review:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-service-activation/apply \
  | jq '.result.status, .event_id'
```

Collect evidence with:

- `/api/v1/system/broadband-service-activation/history`
- support bundle file `api/broadband-service-activation.json`
- support bundle file `api/broadband-service-activation-history.json`
- production readiness key `broadband_service_activation`

## Production Boundary

Engineering is complete when code, validation, tests, docs, API/UI, migration,
runtime status, and evidence are implemented and passing. Real BNG route
publish/withdraw, multicast forwarding, FreeRADIUS production Linux interop,
HA failover, scale, soak, security audit, production deployment, and customer
acceptance are release certification tasks.
