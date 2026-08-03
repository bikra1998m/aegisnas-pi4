# NAS-0045 Release Certification Checklist

NAS-0045 software implementation is complete when code, migrations, APIs, UI,
tests, CI wiring, and documentation pass. The following items require external
systems, production Linux packages, real access devices, controllers, or
long-running environments and do not block engineering closure.

## Scope

- Feature: Vendor dynamic-action compiler
- RFCs: RFC 2865, RFC 3576, RFC 5176
- Vendor packs: Cisco, Aruba, Juniper, Ruckus, Fortinet, MikroTik, Huawei, and
  H3C/Comware
- Software evidence: `go test` coverage for vendor action preview, fail-closed
  validation, Type 26 VSA encoding, DB schema v50, durable queue evidence,
  admin API, OpenAPI, readiness, support bundle, and UI build.

## External Certification

- Capture FreeRADIUS 3.2.x packet traces for compiled vendor CoA-Request and
  Disconnect-Request packets for every claimed pack.
- Validate Cisco reauth, role, ACL, QoS, quarantine, and disconnect behavior on
  exact IOS-XE, Catalyst, WLC, Meraki, or ISE-interoperable firmware before
  claiming that product family.
- Validate Aruba role, VLAN, ACL/filter, reauth, quarantine, and disconnect
  behavior on exact AOS-CX, ArubaOS, Instant, or controller firmware before
  claiming that product family.
- Validate Juniper filter, local-user, QoS, VLAN, reauth, and disconnect
  behavior on exact EX/SRX/Mist-supported firmware before claiming that product
  family.
- Validate Ruckus, Fortinet, MikroTik, Huawei, and H3C/Comware action semantics
  on exact firmware versions before claiming production interoperability.
- Confirm each compiled VSA matches the vendor dictionary name, PEN, type,
  payload type, byte length, cardinality, and duplicate behavior.
- Confirm NAK and Error-Cause handling for unsupported or rejected vendor
  actions on each certified target.
- Confirm proxy and RadSec routed vendor actions preserve required Proxy-State
  behavior and do not downgrade secure routes.
- Run HA restart and failover drills with queued vendor-action records.
- Run sustained replay, timeout/backoff, and duplicate idempotency soak tests.
- Record security review for RBAC, confirmation gates, tenant scoping, secret
  redaction, support-bundle redaction, and audit logs.
- Attach support bundles with `api/dac-client.json`,
  `api/dac-client-history.json`, production readiness output, packet captures,
  firmware versions, FreeRADIUS package version, dictionary release profile,
  and topology notes.

## Release Sign-Off

- FreeRADIUS interoperability evidence attached.
- Vendor device or controller evidence attached for each claimed vendor/action.
- Proxy/RadSec route evidence attached for every claimed routed action.
- HA and rollback evidence attached.
- Performance and soak evidence attached.
- Security review complete.
- Customer acceptance scope recorded.
