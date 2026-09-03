# NAS-0068 Release Certification Checklist

NAS-0068 software implementation is complete when
`make test-broadband-vendor-pack` passes and
`/api/v1/system/broadband-vendor-pack` reports 100% software completion. The
following items require external systems, physical devices, production-like
infrastructure, or customer acceptance and are release certification activities
only.

## Evidence Capture

- [ ] Record `/api/v1/system/broadband-vendor-pack/record` evidence for the
  exact build, source hash, and pack fingerprint.
- [ ] Export a support bundle containing `api/broadband-vendor-pack.json`.
- [ ] Export a support bundle containing
  `api/broadband-vendor-pack-history.json`.
- [ ] Archive the FreeRADIUS dictionary release profile used for the test run.

## FreeRADIUS Interoperability

- [ ] Install the generated AegisNAS dictionary on a production Linux
  FreeRADIUS host.
- [ ] Validate Huawei, H3C, and ZTE dictionary loading with `radiusd -XC` or
  `freeradius -XC`.
- [ ] Replay Access-Request, Access-Accept, Accounting-Request, CoA, and
  Disconnect packet fixtures for each vendor pack.
- [ ] Capture packet traces proving exact VSA numbers, lengths, values, and
  response codes.

## Huawei Certification

- [ ] Validate Huawei BRAS/BNG behavior for subscriber state, QoS, address
  pools, routes, NAT, deterministic port blocks, NAT64, portal, accounting, and
  command authorization.
- [ ] Validate Huawei MA/CloudEngine/WLAN/iMaster behavior where campus or
  controller workflows consume these VSAs.
- [ ] Confirm Huawei input/output rate directionality and units against target
  firmware.
- [ ] Confirm Huawei password, DPSK, and web-authentication fields are never
  logged or stored as cleartext in production observability.
- [ ] Validate CoA reauthorization and Disconnect behavior on supported Huawei
  firmware.

## H3C Certification

- [ ] Validate H3C Comware and iMC behavior for role, group, portal URL, ITA
  policy, average/peak rates, route, address, NAT, and multicast fields.
- [ ] Validate H3C BRAS/BNG behavior for public IP address, port-block,
  subscriber, DNS, VRF, accounting, and backup NAS fields.
- [ ] Confirm H3C input/output rate directionality and units against target
  firmware.
- [ ] Validate H3C AVPair route, NAT64, translation, ACL, and policy strings
  against every published product profile.
- [ ] Validate CoA reauthorization and Disconnect behavior on supported H3C
  firmware.

## ZTE Certification

- [ ] Validate ZTE ZX/BNG behavior for PPPoE URL, privilege role, QoS profile,
  SCR rates, IPv6 SCR rates, DNS, domain, VPN, multicast, and tunnel controls.
- [ ] Confirm ZTE SCR directionality and units against target firmware.
- [ ] Validate multicast group limits and tunnel controls under subscriber
  reconnect and accounting load.
- [ ] Validate CoA reauthorization and Disconnect behavior on supported ZTE
  firmware.

## HA, Performance, And Security

- [ ] Run active/standby failover during Huawei/H3C/ZTE authentication,
  accounting, route, NAT, and CoA traffic.
- [ ] Run performance benchmarks on low-spec, branch, and enterprise hardware
  profiles.
- [ ] Run long-duration soak tests with mixed Huawei, H3C, and ZTE subscriber
  sessions.
- [ ] Run log review confirming redaction of Huawei credential-like evidence
  and bounded storage for all VSA values.
- [ ] Complete external security review for packet parsing, AVPair parsing,
  route/NAT rendering, support-bundle evidence, and controller boundaries.

## Release Sign-off

- [ ] Attach controller screenshots, packet captures, support bundles, and test
  transcripts to the release record.
- [ ] Record firmware, controller, and BRAS/BNG versions for every certified
  product.
- [ ] Obtain customer or lab acceptance for each published hardware claim.
- [ ] Mark NAS-0068 hardware/controller claims as certified only for the tested
  versions and deployment profiles.
