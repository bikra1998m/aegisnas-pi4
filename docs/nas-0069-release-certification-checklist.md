# NAS-0069 Release Certification Checklist

NAS-0069 software implementation is complete when `make test-nokia-alu-pack`
passes and `/api/v1/system/nokia-alu-pack` reports 100% software completion.
The following items require external systems, physical devices,
production-like infrastructure, or customer acceptance and are release
certification activities only.

## Evidence Capture

- [ ] Record `/api/v1/system/nokia-alu-pack/record` evidence for the exact
  build, source hash, and pack fingerprint.
- [ ] Export a support bundle containing `api/nokia-alu-pack.json`.
- [ ] Export a support bundle containing `api/nokia-alu-pack-history.json`.
- [ ] Archive the FreeRADIUS dictionary release profile used for the test run.

## FreeRADIUS Interoperability

- [ ] Install the generated AegisNAS dictionary on a production Linux
  FreeRADIUS host.
- [ ] Validate Nokia, Alcatel, Alcatel-ESAM, Alcatel-Lucent-Service-Router, and
  ALU-AAA dictionary loading with `radiusd -XC` or `freeradius -XC`.
- [ ] Replay Access-Request, Access-Accept, Accounting-Request, CoA, and
  Disconnect packet fixtures for each vendor pack.
- [ ] Capture packet traces proving exact VSA numbers, lengths, values,
  repeated AVPairs, Nokia BCD service names, and response codes.

## Nokia SR OS Certification

- [ ] Validate `Nokia-User-Profile` role/profile assignment against target SR
  OS releases.
- [ ] Validate `Nokia-Service-Name` swapped-nibble BCD values against service
  authorization workflows.
- [ ] Validate `Nokia-AVPair` route, VRF, address pool, delegated IPv6, NAT64,
  translation, port-block, ACL, logging, and accounting strings.
- [ ] Confirm OCS, charging, APN, and tunnel-challenge rows are redacted or
  bounded as expected in logs, events, and support bundles.
- [ ] Validate CoA reauthorization and Disconnect behavior on supported Nokia
  firmware.

## Alcatel AAT Certification

- [ ] Validate AAT PPP address, DNS, WINS, and default-router rows against
  target access-server firmware.
- [ ] Validate `AAT-Vrouter-Name`, QoS, ATM/FR traffic profile, filter, and
  data-filter behavior.
- [ ] Confirm home-agent and mobile-filter password evidence is never logged or
  stored as cleartext.
- [ ] Validate accounting and session evidence under reconnect and failover.

## Alcatel ESAM Certification

- [ ] Validate ESAM VRF, VLAN, QoS profile, DHCP, PPPoE, and xDSL rows against
  target ESAM access-node firmware.
- [ ] Validate TL1, access-node, shelf/slot/port, transport, and provisioning
  fields in accounting and support-bundle evidence.
- [ ] Confirm high-number ESAM VSA formatting and acceptance with packet
  captures.
- [ ] Validate security/posture rows and failure behavior.

## Alcatel-Lucent SR OS Certification

- [ ] Validate `Timetra-Profile`, `Alc-Subsc-ID-Str`,
  `Alc-Subsc-Prof-Str`, `Alc-SLA-Prof-Str`, and `Alc-MSAP-Policy`.
- [ ] Validate SAP/MSAP, SDP/service, DHCP, PPPoE, ANCP, lease, DSL, and
  subscriber identity behavior.
- [ ] Validate BGP policy, VRF, framed route, IPv6, delegated IPv6 pool,
  DHCPv6, RA/SLAAC, and address-pool behavior.
- [ ] Validate NAT, DNAT, outside IPv4, NAT64, deterministic port range, and
  translation logging/accounting behavior.
- [ ] Validate portal URL, redirect, HTTP, WLAN SSID/VLAN, and guest lifecycle
  behavior.
- [ ] Validate `Alc-Nas-Filter-Rule-Shared` ACL rules in ingress and egress
  policy paths.
- [ ] Validate accounting counters, charging, triggered interim updates, and
  CoA/Disconnect on supported firmware.

## ALU-AAA Certification

- [ ] Validate `ALU-AAA-Access-Rule`, `ALU-AAA-AV-Pair`, and
  `ALU-AAA-Service-Profile` against target ALU-AAA deployments.
- [ ] Validate NAS IP, NAS port, client program, client OS, client version, and
  device identity evidence.
- [ ] Validate GSM triplet, AKA quintet, RAND, AUTS, nonce, femto public key
  hash, and key attributes are redacted from cleartext logs and persistence.
- [ ] Validate civic/geospatial location, called-station, event, old/new state,
  timestamp, and delta-session behavior.

## HA, Performance, And Security

- [ ] Run active/standby failover during Nokia/ALU authentication, accounting,
  route, NAT, ACL, BCD service-name, and CoA traffic.
- [ ] Run performance benchmarks on low-spec, branch, and enterprise hardware
  profiles.
- [ ] Run long-duration soak tests with mixed Nokia SR OS, Alcatel AAT, ESAM,
  ALU SR OS, and ALU-AAA sessions.
- [ ] Run log review confirming redaction of GSM/AKA/femto/key material and
  bounded storage for all VSA values.
- [ ] Complete external security review for AVPair parsing, BCD decoding,
  route/NAT rendering, support-bundle evidence, and service-router boundaries.

## Release Sign-off

- [ ] Attach device screenshots, packet captures, support bundles, and test
  transcripts to the release record.
- [ ] Record firmware, controller, AAA, and service-router versions for every
  certified product.
- [ ] Obtain customer or lab acceptance for each published hardware claim.
- [ ] Mark NAS-0069 hardware/controller claims as certified only for the tested
  versions and deployment profiles.
