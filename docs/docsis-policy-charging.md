# CableLabs DOCSIS Policy and Charging

NAS-0097 adds the software lifecycle for CableLabs/DOCSIS cable modem policy,
service-flow authorization, CMTS scope, IPDR charging correlation, and RADIUS
evidence.

## Scope

The implementation models DOCSIS policy and charging as deterministic intent:

- cable modem profiles with DOCSIS version, CMTS profile, provisioning class,
  service tier, accounting class, policy profile, vendor packs, and RADIUS
  attributes
- DOCSIS service flows with direction, scheduler, service-flow ID, QoS profile,
  rate/burst bounds, packet classifier, and CableLabs attributes
- CMTS profiles with CMTS ID, vendor, management domain, DHCP relay,
  accounting endpoint, CoA profile, and RADIUS attributes
- charging policies with billing model, rating group, quota policy, IPDR export,
  CoA profile, and quota/policy attributes

The feature depends on NAS-0092 grouped telecom AVP evidence, NAS-0094 charging
correlation, NAS-0087 broadband QoS service flows, and dynamic authorization
when enforcement mode is enabled.

## APIs

```text
GET  /api/v1/system/docsis-policy
POST /api/v1/system/docsis-policy/preview
POST /api/v1/system/docsis-policy/apply
GET  /api/v1/system/docsis-policy/history
```

Preview records an auditable evidence event without changing effective rows.
Apply records effective modem, service-flow, CMTS, and charging-policy rows in
`docsis_policy_profiles`, records the event in `docsis_policy_events`, and
updates runtime status under `docsis_policy_charging`.

## Configuration

Configuration lives under `mobile.docsis`. Enforcement mode requires:

- `mobile.grouped_avps.enabled`
- `mobile.charging.enabled`
- `broadband.qos_service_flows.enabled`
- `radius.dynamic_auth.enabled` or `radius.dynamic_auth.outbound_enabled`
- at least one enabled modem profile, service flow, CMTS profile, and charging
  policy
- `hash_device_ids` when `redact_device_ids` is enabled

## Release Boundary

Software implementation is complete when code, schema, APIs, UI, automation,
tests, and documentation pass. The following remain external release
certification activities:

- live CMTS and cable modem interoperability
- DOCSIS provisioning-system validation
- IPDR mediation and billing settlement proof
- CableLabs VSA packet captures for Access-Request, Access-Accept,
  Accounting, CoA, and Disconnect
- FreeRADIUS production Linux interoperability
- HA, scale, soak, security, and customer acceptance evidence
