# DHCP Relay, Snooping, Option 82, And Source Guard

NAS-0089 implements the software lifecycle for DHCP relay governance, DHCP
snooping bindings, RFC 3046 Option 82 identity, IP source guard policy, and
RADIUS correlation. It models trusted and untrusted access ports, relay agents,
Option 82 stamping and verification, source-guard enforcement intent, durable
binding evidence, support bundle capture, production readiness, and admin UI
operation.

## Scope

Software completion includes:

- `broadband.dhcp_security` configuration and validation
- dependency checks for DHCP, subscriber state, address leases, SQL accounting,
  accounting services, and dynamic authorization
- relay-agent metadata for interface, VLAN, gateway, server group, VRF, circuit
  ID, remote ID, trust, and vendor packs
- DHCP snooping port bindings for interface, VLAN, trust state, circuit ID,
  remote ID, tenant, subscriber product, max leases, and source guard policy
- Option 82 rules for append, replace, verify, strip, preserve, and drop intent
- source guard policies for monitor/enforce/strict behavior, interface and VLAN
  scope, unknown binding handling, IPv6 readiness, violation action, and CoA
  recovery action
- RADIUS accounting correlation rules for `Class`, `NAS-Port-Id`, and
  `Calling-Station-Id`
- compiled standards and vendor evidence for RFC 3046 relay-agent information,
  Cisco, Juniper/ERX, Huawei/H3C, Nokia/Alcatel, and AegisNAS attributes
- preview/apply APIs and RBAC
- durable event and effective binding tables
- runtime status, support bundle, OpenAPI, production readiness, UI, CI, and
  automated tests

External certification remains outside software completion and is tracked in
`nas-0089-release-certification-checklist.md`.

## Configuration

The feature is configured under `broadband.dhcp_security`.

Key fields:

- `enabled`: activates preview/apply governance
- `mode`: `monitor` or `enforce`
- `require_dhcp`: requires the local DHCP service configuration
- `require_subscriber_state`: requires subscriber lifecycle state
- `require_address_leases`: requires durable address lease ownership
- `require_accounting`: requires SQL accounting and service correlation
- `require_dynamic_auth`: requires CoA/Disconnect recovery for source guard
- `relay_enabled`: requires configured relay agents when enforcing
- `snooping_enabled`: requires configured DHCP snooping ports when enforcing
- `source_guard_enabled`: requires source guard policy coverage
- `option82_required`: requires at least one enabled Option 82 rule
- `drop_unknown_bindings`: records fail-closed intent for unknown binding rows
- `trusted_uplink_required`: requires at least one trusted uplink/access-node
  port before enforcement
- `option82_policy`: `append`, `replace`, `verify`, `strip`, or `preserve`
- `relay_agents`: relay interfaces and Option 82 stamping metadata
- `ports`: trusted and untrusted DHCP snooping binding rows
- `option82_rules`: match/action rules for relay-agent information
- `source_guard_policies`: binding enforcement and recovery behavior
- `radius_correlation`: attributes and accounting stages used to carry binding
  identity into RADIUS evidence

Use monitor mode until preview output, support bundle evidence, packet captures,
and access-node behavior agree with the target network.

## APIs

```text
GET  /api/v1/system/broadband-dhcp-security
POST /api/v1/system/broadband-dhcp-security/preview
POST /api/v1/system/broadband-dhcp-security/apply
GET  /api/v1/system/broadband-dhcp-security/history
```

Read-only, guest-admin, ops-admin, and super-admin users may read, preview, and
list history. Only ops-admin and super-admin users may apply.

## Persistence

NAS-0089 adds:

- `broadband_dhcp_security_events`
- `broadband_dhcp_security_bindings`

Events store preview/apply evidence, plan fingerprints, relay, port, trusted
port, Option 82, source guard, correlation, compliance, blocker, warning, and
compiled option counts. Effective binding rows store binding key, port,
interface, VLAN, trust, circuit ID, remote ID, subscriber product, tenant,
relay agent, source guard policy, compiled option JSON, source event, plan
fingerprint, install/withdraw timestamps, and status.

## Vendor Behavior

The normalized model compiles standards evidence for RFC 3046
`DHCP-Relay-Agent-Information`, `Agent-Circuit-Id`, `Agent-Remote-Id`, and
RADIUS `Class` correlation. Vendor pack evidence adds:

- `Cisco-AVPair` for Cisco DHCP snooping and Option 82 behavior
- `Juniper-AV-Pair` for Juniper/ERX relay-agent information evidence
- `Huawei-AVpair` for Huawei/H3C DHCP relay and snooping evidence
- `Nokia-AVPair` for Nokia/Alcatel DHCP relay information evidence
- `AegisNAS-Subscriber-Product` for product and subscriber service correlation

Live DHCP relay insertion, switch or OLT DHCP snooping, and hardware source
guard enforcement remain release certification items instead of silent software
claims.

## Operations

Preview first:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-dhcp-security/preview \
  | jq '.report.status, .report.summary, .report.ports'
```

Apply after review:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-dhcp-security/apply \
  | jq '.result.status, .event_id'
```

Collect evidence with:

- `/api/v1/system/broadband-dhcp-security/history`
- support bundle file `api/broadband-dhcp-security.json`
- support bundle file `api/broadband-dhcp-security-history.json`
- production readiness key `broadband_dhcp_security`

## Production Boundary

Engineering is complete when code, validation, tests, docs, API/UI, migration,
runtime status, and evidence are implemented and passing. Real access-node DHCP
relay, snooping, Option 82 packet insertion, source guard enforcement,
FreeRADIUS production Linux interop, HA failover, scale, soak, security audit,
production deployment, and customer acceptance are release certification tasks.
