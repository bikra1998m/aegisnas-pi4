# NAS-0092 Release Certification Checklist

Software engineering for NAS-0092 is complete. This checklist tracks external
validation that requires real systems, third-party software, physical hardware,
customer environments, or certification activity.

## External Validation

- [ ] Capture positive and negative FreeRADIUS packets for 3GPP grouped and
  mobile-core attributes on production Linux.
- [ ] Capture positive and negative FreeRADIUS packets for 3GPP2 grouped quota,
  flow, and QoS attributes on production Linux.
- [ ] Validate Starent/Cisco ASR packet-core scope with exact product and
  firmware details.
- [ ] Validate Ericsson/Redback packet-core or BNG scope with exact product and
  firmware details.
- [ ] Validate WiMAX grouped service-flow scope with an emulator or real WiMAX
  access platform.
- [ ] Confirm redaction and SHA-256 evidence behavior in support bundles and
  exported logs.
- [ ] Run HA failover while preview/apply/history events are being written.
- [ ] Run packet fuzz, malformed grouped AVP, oversized payload, and recursion
  depth drills.
- [ ] Run scale and soak tests for high-cardinality grouped AVP histories.
- [ ] Complete external security review for raw-evidence retention, privacy,
  and support-bundle disclosure.
- [ ] Record customer acceptance for the exact vendor/product/firmware scope.

## Certification Evidence

Each certification run must record:

- date, operator, topology, product, model, firmware, and software commit
- dictionary release and registry SHA-256
- packet captures and decoded evidence
- pass/fail result and remediation notes
- HA, rollback, and upgrade evidence
- signed approval or waiver
