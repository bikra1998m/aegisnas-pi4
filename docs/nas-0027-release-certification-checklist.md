# NAS-0027 Release Certification Checklist

## Software Implementation

- [x] Config schema and validation for
  `onboarding.certificate_lifecycle`.
- [x] Deterministic certificate lifecycle evaluator for EST, SCEP, BYOD,
  admin, and API enrollment entry points.
- [x] CSR parsing, signature proof-of-possession, key type, key size, curve,
  subjectAltName, device binding, template, issuer, renewal, revocation, and
  escrow policy checks.
- [x] Hashed event history in `certificate_lifecycle_events`.
- [x] Current hashed certificate inventory in
  `certificate_lifecycle_inventory`.
- [x] REST API, OpenAPI, RBAC, support-bundle capture, system status, and
  production-readiness integration.
- [x] Access Settings controls and Dashboard runtime visibility.
- [x] Unit, integration, API, migration, readiness, support-bundle, and CI
  target coverage.
- [x] Operator, API, external AAA, roadmap, and backlog documentation.

Software Implementation: 100% Complete

Engineering Implementation: 100% Complete

Ready For External Validation: Yes

## External Certification / Deployment

- [ ] Obtain production CA and security approval for the intended issuer model.
- [ ] Validate EST enrollment against the production Linux/FreeRADIUS runtime.
- [ ] Validate SCEP enrollment against the production Linux/FreeRADIUS runtime.
- [ ] Validate BYOD onboarding with supported Apple, Windows, Android, and
  Linux supplicants.
- [ ] Validate Microsoft ADCS/NPS, Cisco ISE, Aruba ClearPass, Jamf, Intune,
  Fortinet, Juniper Mist, and UniFi interoperability where claimed.
- [ ] Capture packet traces for CSR, renewal, revocation, EAP-TLS, CRL, and
  OCSP positive and negative paths.
- [ ] Run issuer-rotation drills with active and staged issuers.
- [ ] Run CRL publication outage and OCSP responder outage drills.
- [ ] Run revoked, expired, weak-key, missing-SAN, mismatched-device, escrow,
  and renewal-window negative tests.
- [ ] Run HA failover while enrollment and renewal requests are active.
- [ ] Run large renewal-batch performance tests at supported inventory limits.
- [ ] Run long-duration soak tests for event retention and inventory churn.
- [ ] Complete security review for private-key handling, escrow governance,
  identity hashing, support-bundle privacy, and fail-closed behavior.
- [ ] Retain support bundles with `api/certificate-lifecycle.json`.
- [ ] Obtain customer acceptance evidence for claimed vendor/product/firmware
  combinations.
