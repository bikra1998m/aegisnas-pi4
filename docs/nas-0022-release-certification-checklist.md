# NAS-0022 Release Certification Checklist

## Software Implementation

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes

Completed software scope:

- Typed EAP framework configuration, validation, defaults, and example config.
- EAP method catalog for generated PEAP, TTLS, TLS and planned TEAP, FAST, PWD, SIM, AKA, AKA-prime.
- Deterministic method evaluation for allowed methods, inner methods, identity binding, certificate requirements, unsupported methods, monitor mode, and fail-closed enforcement.
- FreeRADIUS EAP generation integrated with framework timeout, fragment size, max sessions, status evidence, and enforce-mode blocking for non-generated planned methods.
- Schema v27 `eap_method_events` with hashed identity fields and bounded retention.
- Admin API report and evaluation endpoints, OpenAPI, RBAC, system status, production readiness, and support bundle capture.
- Admin UI Access Settings controls and Dashboard runtime status.
- Unit and integration tests for config, DB, framework evaluation, FreeRADIUS generation, API, RBAC, readiness, OpenAPI, support bundle, and CI.
- CI target `make test-eap-framework`.

## External Certification / Deployment

- [ ] Run `freeradius -XC` on production Linux with the generated `mods-enabled/eap`.
- [ ] Capture EAP Identity, NAK, Success, Failure, PEAP, TTLS, and TLS packet traces.
- [ ] Validate Windows, macOS, iOS, Android, Linux, and embedded supplicants for each enabled method.
- [ ] Validate Cisco, Aruba, Ruckus, Extreme, Juniper, Fortinet, UniFi, and generic AP/switch NAS clients.
- [ ] Validate PEAP-MSCHAPv2 against local, LDAP, and Active Directory/winbind identity sources where configured.
- [ ] Validate EAP-TTLS/PAP against local and upstream broker workflows where configured.
- [ ] Validate EAP-TLS with CRL or OCSP before claiming certificate production readiness.
- [ ] Run HA failover while EAP conversations are active.
- [ ] Run load, timeout, fragmentation, malformed-packet, replay, and downgrade drills.
- [ ] Run customer acceptance testing for the published supported method matrix.

External validation does not block closure of NAS-0022 software engineering work.
