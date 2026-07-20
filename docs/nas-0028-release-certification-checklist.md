# NAS-0028 Release Certification Checklist

## Software Implementation

- [x] Supplicant lifecycle configuration and validation.
- [x] Password expiry and password-change policy evaluation.
- [x] Password verifier compatibility enforcement.
- [x] Signed profile package generation for Windows, macOS, iOS, Android, and Linux.
- [x] Trust-anchor pinning and RADIUS server-name policy.
- [x] Admin API status, evaluation, and profile rendering endpoints.
- [x] Captive onboarding portal profile download route.
- [x] Database event history and profile-delivery inventory.
- [x] System status, production readiness, OpenAPI, RBAC, support bundle, UI, and CI wiring.
- [x] Unit, config, DB, API, migration, readiness, OpenAPI, RBAC, and support-bundle tests.
- [x] Operator documentation and example configuration.

Software Implementation: 100% Complete

Engineering Implementation: 100% Complete

Ready for External Validation: Yes

## External Certification / Deployment

- [ ] Install generated profiles on Windows, macOS, iOS, Android, Linux NetworkManager, and at least one embedded supplicant.
- [ ] Validate EAP-TLS profile installation with real CA trust anchors and certificate lifecycle enrollment.
- [ ] Validate PEAP/TTLS password verifier compatibility against Microsoft AD, LDAP, local, and identity-failover paths.
- [ ] Capture password-expired, password-change-required, successful-change, and denied-change packet/application traces.
- [ ] Validate profile signing-key custody, rotation, loss, and rollback.
- [ ] Validate trust-anchor pin rollover and RADIUS server-name mismatch rejection.
- [ ] Validate portal delivery over production HTTPS and reverse-proxy headers.
- [ ] Validate MDM ingestion for Intune, Jamf, Workspace ONE, and Apple profile workflows.
- [ ] Validate AP/controller smoke tests with Cisco, Aruba, UniFi, Ruckus, Fortinet, Mist, and at least one switch vendor.
- [ ] Validate HA failover during profile rendering, password-change prompts, and audit writes.
- [ ] Run performance and abuse tests for concurrent profile rendering and invalid token attempts.
- [ ] Run long-duration soak tests across renewals and password expiry windows.
- [ ] Complete security review for no password storage, profile content disclosure, signature validation, and support-bundle redaction.
- [ ] Record exact OS, supplicant, AP/controller, FreeRADIUS, and firmware versions used for certification.
- [ ] Complete customer acceptance evidence for the supported platform matrix.
