# NAS-0044 Release Certification Checklist

NAS-0044 software implementation is complete when code, migrations, APIs, UI,
tests, CI wiring, and documentation pass. The following items require external
systems, production Linux packages, real access devices, or long-running
environments and do not block engineering closure.

## Scope

- Feature: Proxy CoA and RadSec reverse CoA routing
- RFCs: RFC 2865, RFC 3576, RFC 5176, RFC 6614, RFC 9765
- Software evidence: `go test` coverage for proxy preview, UDP proxy ACK,
  RadSec mTLS ACK, Proxy-State loop rejection, DB schema v49, admin API,
  OpenAPI, readiness, support bundle, and UI build.

## External Certification

- Capture FreeRADIUS 3.2.x packet traces for proxied CoA-Request and
  Disconnect-Request over UDP.
- Capture FreeRADIUS 3.2.x packet traces for RadSec mTLS proxied CoA-Request
  and Disconnect-Request.
- Validate RadSec TLS-PSK active dynamic authorization through the packaged
  FreeRADIUS runtime path before claiming TLS-PSK production support.
- Validate RADIUS/1.1 RadSec dynamic authorization with production FreeRADIUS
  before claiming RADIUS/1.1 active DAC support.
- Run Cisco, Aruba, Juniper, Ruckus, Fortinet, MikroTik, Huawei, UniFi, and
  Mist controller or device smoke tests for proxy ACK, NAK, Error-Cause, and
  timeout behavior.
- Confirm Proxy-State loop marker rejection with a multi-hop proxy lab.
- Confirm transport downgrade policy blocks unsafe mixed UDP/RadSec routes in
  enforce mode.
- Run HA restart and failover drills with queued proxy DAC records.
- Run sustained replay and timeout/backoff soak tests.
- Record security review for secrets, TLS trust anchors, CRL/OCSP policy,
  redaction, RBAC, and audit logs.
- Attach support bundles with `api/dac-client.json`,
  `api/dac-client-history.json`, production readiness output, packet captures,
  firmware versions, FreeRADIUS package version, and topology notes.

## Release Sign-Off

- FreeRADIUS interoperability evidence attached.
- Vendor device or controller evidence attached for each claimed vendor.
- HA and rollback evidence attached.
- Performance and soak evidence attached.
- Security review complete.
- Customer acceptance scope recorded.
