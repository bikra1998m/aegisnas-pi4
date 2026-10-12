# NAS-0092 Telecom Grouped AVP Framework

NAS-0092 adds the software framework for grouped telecom RADIUS attributes and
AVPs used by 3GPP, 3GPP2, Starent/Cisco, Ericsson/Redback, and WiMAX
deployments.

The feature does not claim carrier hardware certification. It provides the
production software layer that later mobile-session, charging, PCRF/PCF,
WiMAX, DOCSIS, and voice features can safely build on.

## Scope

- Vendor scopes for `3GPP`, `3GPP2`, `Starent`, `Ericsson`, and `WiMAX`
- Grouped/nested AVP semantic categories for identity, charging, QoS, and
  policy
- Safe raw evidence policy using redaction lists and SHA-256 digests
- Bounded packet model tied to the NAS-0005 VSA codec
- Database-backed preview/apply/history evidence
- Admin API, OpenAPI, RBAC, production readiness, system status, support
  bundle, and Access Settings visibility

## Configuration

```yaml
mobile:
  grouped_avps:
    enabled: false
    mode: monitor
    fail_closed: true
    require_database: true
    require_vsa_codec: true
    require_attribute_registry: true
    safe_raw_evidence: true
    hash_raw_values: true
    max_depth: 4
    max_payload_bytes: 4096
    max_attributes_per_packet: 4096
    raw_evidence_retention_days: 30
    event_retention_limit: 10000
```

Use `monitor` first. Move to `enforce` only after preview output, safe evidence
policy, release checklist requirements, and downstream feature dependencies are
accepted.

## API

```text
GET  /api/v1/system/mobile-grouped-avps
POST /api/v1/system/mobile-grouped-avps/preview
POST /api/v1/system/mobile-grouped-avps/apply
GET  /api/v1/system/mobile-grouped-avps/history
```

`preview` records a non-mutating event. `apply` records the compiled vendor
scope rows, runtime status, and evidence summary. Support bundles include:

- `api/mobile-grouped-avps.json`
- `api/mobile-grouped-avps-history.json`

## Packet Model

NAS-0092 consumes RADIUS `Vendor-Specific(26)` attributes after packet
hardening and NAS-0005 codec decoding. It maps decoded telecom attributes into
stable software domains:

- identity: IMSI, IMEISV, NAI, and mobile-node identifiers
- charging: charging IDs, characteristics, quota IDs, and session IDs
- QoS: negotiated QoS, DSCP, granted QoS params, and WiMAX descriptors
- policy: RAT, selection mode, rulebase, context, and termination hints

Cleartext subscriber identifiers should not be persisted. The default evidence
policy records redacted metadata and hashes.

## Release Boundary

Software implementation is complete when code, migrations, APIs, UI, docs, and
automated tests pass. The following remain release certification activities:

- carrier packet-core simulator proof
- real 3GPP/3GPP2/Starent/Ericsson/WiMAX captures
- FreeRADIUS production Linux interoperability
- HA failover drills
- scale and soak testing
- external security review
- customer acceptance
