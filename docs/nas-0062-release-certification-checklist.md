# NAS-0062 Release Certification Checklist

NAS-0062 software implementation is complete when code, tests, APIs, UI,
automation, and documentation pass. The items below are external release gates
and do not keep NAS-0062 open for engineering.

## External Certification

- [ ] Record `/api/v1/system/aruba-family-pack/record` evidence for the release
  candidate fingerprint.
- [ ] Validate FreeRADIUS dictionary interoperability on the target production
  Linux image.
- [ ] Capture Access-Accept, Access-Reject, Accounting, CoA, and Disconnect
  packets for ArubaOS, Aruba Central, ClearPass, ArubaOS-Switch,
  Aerohive/Extreme, and Colubris/MSM devices that are in release scope.
- [ ] Confirm Aruba roles, ClearPass CPPM roles, VLANs, named VLANs, NAS filter
  rules, captive portal redirects, AirGroup, MDPS, UBT, QoS, and port-bounce
  behavior on declared firmware versions.
- [ ] Confirm HP/ArubaOS-Switch role, privilege, bandwidth, ACL, egress VLAN,
  Bonjour, URI, command, and port-bounce behavior on declared firmware versions.
- [ ] Confirm Aerohive/Extreme VLAN, profile ID, AVPair, IDM redirect/message,
  client monitor, and PPSK metadata behavior on declared firmware versions.
- [ ] Confirm Colubris/HP MSM intercept behavior on declared firmware versions.
- [ ] Verify secret-bearing MPSK, DPP, PPSK, PMK, and credential attributes never
  appear in clear text in logs, support bundles, UI, API history, or database
  evidence.
- [ ] Run HA failover, rollback, and migration drills.
- [ ] Run load, malformed packet, replay, and long-duration soak tests.
- [ ] Complete security review and customer acceptance testing.

## Release Evidence

- [ ] Support bundle archive with `api/aruba-family-pack.json`.
- [ ] Support bundle archive with `api/aruba-family-pack-history.json`.
- [ ] Packet captures with expected RADIUS attributes.
- [ ] Device/controller firmware matrix.
- [ ] Signed waiver list for attributes not supported by a specific firmware
  target.
- [ ] Release sign-off from operations and security.
