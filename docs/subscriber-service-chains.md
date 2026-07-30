# Subscriber Service Chains

NAS-0032 adds vendor-neutral per-service authorization for subscriber sessions.
One policy decision can now return an ordered `service_chain` with dependent
services such as data access, QoS, ACL/firewall policy, captive portal,
quarantine, routing, IPv6, charging, controller, or lawful-intercept intents.

This feature maps the common broadband and enterprise model used by Juniper
ERX, Huawei, H3C, Nokia SR OS / Alcatel-Lucent service routers, Starent, and
similar BNG/NAS platforms into AegisNAS policy semantics. FreeRADIUS
dictionaries provide many vendor names for these concepts, but AegisNAS stores
and evaluates the neutral service intent first, then lets vendor packs or
controller integrations render device-specific attributes.

## Policy Model

Policy rules accept a `service_chain` array. Each service has:

- `key`: stable unique service key for the chain
- `sequence`: activation order
- `type`: `access`, `subscriber`, `data`, `voice`, `video`, `qos`, `acl`,
  `firewall`, `captive_portal`, `hotspot`, `quarantine`, `routing`, `ipv6`,
  `lawful_intercept`, `charging`, or `controller`
- `action`: `activate`, `authorize`, or `deactivate`
- optional dependency list through `depends_on`
- optional role, VLAN, bandwidth, ACL, portal, filter, tenant, device group,
  accounting class, session limit, and bounded string attributes

Validation rejects duplicate service keys, invalid tokens, forward
dependencies, VLANs outside 1..4094, negative session limits, oversized
attribute maps, and chains longer than `policy.max_service_chain_length`.

## APIs

```text
GET  /api/v1/system/subscriber-service-chains
POST /api/v1/system/subscriber-service-chains/preview
POST /api/v1/system/subscriber-service-chains/activate
POST /api/v1/system/subscriber-service-chains/{chainID}/rollback
```

Preview evaluates the active policy and returns the derived chain, validation,
policy-set hash, request hash, and deterministic chain ID without writing
state. Activation requires an allow decision and valid non-empty chain; it then
writes chain, event, and accounting-start evidence. Rollback is restricted to
`super_admin` and records rollback events while stopping active service
accounting rows.

## Persistence

Schema v37 adds:

- `policy_rules.service_chain_json`
- `policy_simulation_analyses.service_chain_change_count`
- `subscriber_service_chains`
- `subscriber_service_events`
- `subscriber_service_accounting`

Usernames and Calling-Station-Ids are hashed before persistence. Full service
intent JSON is retained for rollback and support evidence.

## RADIUS Product VSAs

`dictionary.aegisnas` now includes:

- `AegisNAS-Service-Chain`
- `AegisNAS-Service-Name`

The reply renderer emits a compact service-chain summary and repeated service
names when the `aegisnas` vendor pack is active. Large, device-specific
encodings remain the responsibility of vendor packs and later BNG/controller
features.

## Operations

The service-chain report appears in:

- `/api/v1/system/status` under `radius.subscriber_service_chains`
- `/api/v1/system/production-readiness` as `subscriber_service_chains`
- support bundles as `api/subscriber-service-chains.json`
- Access Settings as the Subscriber Service Chains panel

Software implementation is complete when unit, DB, API, migration, RADIUS
rendering, frontend build, and documentation tests pass. Real BNG/AP/controller
interoperability, packet captures, HA drills, soak tests, and performance
benchmarks belong to `nas-0032-release-certification-checklist.md`.
