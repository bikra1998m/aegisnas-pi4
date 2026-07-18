# NAS-0025 Release Certification Checklist

NAS-0025 software engineering is complete when code, tests, API, UI,
configuration, documentation, CI, and migrations are merged. The items below
are external release certification and deployment evidence, not blockers for
closing the software roadmap item.

## Software Implementation

- [x] Code complete
- [x] Database migration complete
- [x] APIs complete
- [x] Admin UI complete
- [x] Configuration defaults and validation complete
- [x] Documentation complete
- [x] Unit tests complete
- [x] Integration tests complete
- [x] Packet-generation tests complete
- [x] CI target complete
- [x] Engineering Implementation: 100% Complete
- [x] Ready for External Validation: Yes

## External Certification / Deployment

- [ ] Validate generated `mods-enabled/eap` with FreeRADIUS on production Linux
  with `rlm_eap_sim`, `rlm_eap_aka`, and `rlm_eap_aka_prime` installed.
- [ ] Capture EAP-SIM full-auth packet traces with accepted, rejected, missing
  vector, stale vector, and replay paths.
- [ ] Capture EAP-AKA packet traces with accepted, rejected, AUTN failure,
  MAC failure, RES failure, resync accepted, and resync rejected paths.
- [ ] Capture EAP-AKA-prime packet traces with network-name and KDF success and
  failure paths.
- [ ] Validate vector-provider integration with the production HSS, HLR, UDM,
  or approved static-file lab source.
- [ ] Validate vector-provider outage behavior with fail-closed and monitor
  modes.
- [ ] Validate pseudonym and fast reauth identity behavior with real supplicants.
- [ ] Validate Passpoint or carrier offload roaming behavior where applicable.
- [ ] Validate representative AP/controller families and firmware versions.
- [ ] Validate HA failover during active SIM/AKA exchanges.
- [ ] Validate retention, support-bundle redaction, and privacy handling for
  subscriber identities.
- [ ] Run performance, soak, malformed-packet, and replay-cache tests.
- [ ] Complete security review for vector-provider transport, secrets, and audit
  redaction.
- [ ] Publish supported carrier, device, controller, firmware, and FreeRADIUS
  scope before customer-facing production claims.
