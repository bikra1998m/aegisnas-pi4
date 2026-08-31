# NAS-0067 Release Certification Checklist

NAS-0067 software implementation is complete when `make test-access-vendor-pack`
passes and `/api/v1/system/access-vendor-pack` reports 100% software
completion. The following items require external systems, physical devices,
production-like infrastructure, or customer acceptance and are release
certification activities only.

## Evidence Capture

- [ ] Record `/api/v1/system/access-vendor-pack/record` evidence for the exact
  build, source hash, and pack fingerprint.
- [ ] Export a support bundle containing `api/access-vendor-pack.json`.
- [ ] Export a support bundle containing `api/access-vendor-pack-history.json`.
- [ ] Archive the FreeRADIUS dictionary release profile used for the test run.

## FreeRADIUS Interoperability

- [ ] Install the generated AegisNAS dictionary on a production Linux
  FreeRADIUS host.
- [ ] Validate Cambium, TP-Link, and D-Link dictionary loading with
  `radiusd -XC` or `freeradius -XC`.
- [ ] Replay Access-Request, Access-Accept, Accounting-Request, CoA, and
  Disconnect packet fixtures for each vendor pack.
- [ ] Capture packet traces proving exact VSA numbers, lengths, values, and
  response codes.

## Cambium Certification

- [ ] Validate cnMaestro policy behavior for role, VLAN, rate, quota, and
  walled-garden assignments.
- [ ] Validate ePMP or PMP subscriber module behavior for authorization classes
  and traffic-class accounting TLVs.
- [ ] Confirm Cambium `Recv`/`Xmit` directionality against target firmware.
- [ ] Confirm Cambium quota and gigword rollover behavior under accounting
  load.
- [ ] Validate CoA reauthorization and Disconnect behavior on supported
  Cambium firmware.

## TP-Link Omada Certification

- [ ] Validate Omada controller site, group, redirect URL, and portal access
  status behavior.
- [ ] Validate EAP AP, JetStream switch, and Omada gateway behavior when each
  supported attribute is present.
- [ ] Confirm TPLink receive/transmit directionality against target firmware.
- [ ] Confirm authentication-key octets are never logged or stored as cleartext
  in production observability.
- [ ] Validate CoA reauthorization and Disconnect behavior on supported Omada
  controller and device firmware.

## D-Link / Nuclias Certification

- [ ] Validate D-Link switch 802.1X and MAB behavior for user level, VLAN name,
  VLAN ID, 802.1p priority, and ingress/egress bandwidth.
- [ ] Validate ACL profile, ACL rule, and ACL script behavior on target switch
  firmware.
- [ ] Validate Nuclias Connect or Nuclias Cloud behavior where controller
  workflows consume these VSAs.
- [ ] Validate CoA reauthorization and Disconnect behavior on supported D-Link
  firmware.

## HA, Performance, And Security

- [ ] Run active/standby failover during access-vendor authentication,
  accounting, and CoA traffic.
- [ ] Run performance benchmarks on low-spec, branch, and enterprise hardware
  profiles.
- [ ] Run long-duration soak tests with mixed Cambium, TP-Link, and D-Link
  sessions.
- [ ] Run log review confirming redaction of TP-Link authentication-key
  evidence and bounded storage for all VSA values.
- [ ] Complete external security review for packet parsing, ACL compilation,
  and support-bundle evidence.

## Release Sign-off

- [ ] Attach controller screenshots, packet captures, support bundles, and test
  transcripts to the release record.
- [ ] Record firmware and controller versions for every certified product.
- [ ] Obtain customer or lab acceptance for each published hardware claim.
- [ ] Mark NAS-0067 hardware/controller claims as certified only for the tested
  versions and deployment profiles.
