# NAS-0005 Release Certification Checklist

NAS-0005 software implementation is complete. The items below require external environments, real firmware, third-party releases, lab hardware, security review, or production deployment evidence. They do not block development of NAS-0006.

## Packet And FreeRADIUS Validation

- [ ] Run FreeRADIUS production Linux interoperability tests for standard `format=1,1` VSAs.
- [ ] Run packet capture validation for packed repeated VSAs, separate repeated VSAs, malformed vendor lengths, and oversized payloads.
- [ ] Validate `format=1,0`, `format=1,1`, `format=1,2`, `format=2,0`, `format=2,1`, `format=2,2`, `format=4,0`, `format=4,1`, and `format=4,2` vectors against a pinned FreeRADIUS release.
- [ ] Archive golden request, accept, reject, accounting, CoA, and disconnect packet vectors with release artifacts.

## Vendor And Firmware Validation

- [ ] Test Cisco, Aruba/HPE, Juniper, Ruckus, Fortinet, MikroTik, Huawei/H3C, Nokia/Alcatel, WiMAX, 3GPP/3GPP2, and Starent/Cisco mobile-core packet vectors where hardware or simulators are available.
- [ ] Attach exact vendor, model, firmware, controller, FreeRADIUS, packet capture, and expected-result evidence to the release record.
- [ ] Confirm tagged values are interpreted correctly by every vendor that declares tagged VSA behavior.
- [ ] Confirm grouped/OID values remain byte-for-byte stable through proxy and replay paths once NAS-0006 pass-through is implemented.

## HA And Operations

- [ ] Compare `/api/v1/system/vsa-codec` source hashes across HA nodes before upgrade and after rollback.
- [ ] Run rolling upgrade, rollback, and split-brain drills with mixed repeated and grouped VSA traffic.
- [ ] Run long-duration malformed-packet soak tests and confirm no panic, unbounded memory growth, or silent compatibility claim promotion.
- [ ] Confirm support bundles include codec summaries without secrets or raw credential-bearing attributes.

## Security And Governance

- [ ] Review malformed length, nested TLV depth, tag range, oversized value, and repeated-count handling.
- [ ] Run fuzzing and crash triage for vendor payload decode paths.
- [ ] Confirm product documentation does not represent codec readiness as certified vendor feature parity.
- [ ] Record customer acceptance evidence for every deployment that publishes codec-dependent compatibility claims.
