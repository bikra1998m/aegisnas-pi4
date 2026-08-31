# NAS-0065 Release Certification Checklist

This checklist contains only external validation and release evidence for the
Fortinet and Palo Alto security pack. It does not block NAS-0065 engineering
completion after software, tests, docs, automation, and CI are complete.

## Software Evidence

- [x] Pinned FreeRADIUS 3.2.8 registry rows are parsed for Fortinet and
  PaloAlto.
- [x] NAS-0065 report validates all 42 pinned dictionary rows with zero software
  blockers.
- [x] Fortinet product scopes cover FortiGate, FortiWiFi, FortiAuthenticator,
  FortiNAC, FortiAP, FortiSwitch, FortiDeceptor/FDD, FortiWAN, and host-port
  AVPair policy.
- [x] Palo Alto product scopes cover PAN-OS, User-ID, GlobalProtect, and
  Panorama administrative domains.
- [x] Inbound parser, outbound renderer, Fortinet dynamic-action compiler,
  typed pass-through, AVPair grammar, FAC redaction, API, UI, database evidence,
  OpenAPI, RBAC, readiness, support bundle, Makefile, and CI wiring are
  complete.

## External Certification

- [ ] Record `/api/v1/system/fortinet-paloalto-pack/record` evidence for the
  release candidate.
- [ ] Export a support bundle containing `api/fortinet-paloalto-pack.json`.
- [ ] Export a support bundle containing
  `api/fortinet-paloalto-pack-history.json`.
- [ ] Run FreeRADIUS interoperability on the production Linux package with the
  generated dictionary/profile set.
- [ ] Validate FortiGate and FortiWiFi group, VDOM, access profile, client IP,
  web filter, application control, tenant, FortiWAN AVPair, host-port AVPair,
  firewall, VPN, and CoA behavior on supported product and firmware versions.
- [ ] Validate FortiAuthenticator FAC auth status, token, and challenge flows,
  including redaction in logs, APIs, UI, and support bundles.
- [ ] Validate FortiNAC posture, quarantine, role, VLAN, and accounting behavior
  on supported product and firmware versions.
- [ ] Validate FortiAP and FortiSwitch SSID, AP name, WTP ID, device MAC,
  association time, interface, and controller accounting behavior.
- [ ] Validate FortiDeceptor/FDD admin role, trusted hosts, SPP name, SPP
  policy group, API access, and admin privilege behavior.
- [ ] Validate PAN-OS administrative role and access-domain handling.
- [ ] Validate Panorama administrative role and access-domain handling.
- [ ] Validate Palo Alto User-ID group, domain, client source IP, and accounting
  correlation.
- [ ] Validate GlobalProtect client OS, hostname, source IP, and client version
  correlation.
- [ ] Capture Access-Accept, Accounting, CoA, Disconnect, and negative packet
  traces for every supported product scope.
- [ ] Run HA failover drills while preserving certification event history and
  controller sync state.
- [ ] Run performance and soak tests for expected auth/accounting/CoA load.
- [ ] Complete security review for FAC token and challenge redaction, logs,
  support bundles, API output, credential references, and controller tokens.
- [ ] Complete customer or lab acceptance for the exact vendor, product,
  firmware, topology, controller, and subscription versions claimed in release
  notes.

## Release Artifacts

- [ ] Certification report JSON
- [ ] Support bundle archive
- [ ] FreeRADIUS validation output
- [ ] Packet captures
- [ ] FortiGate or FortiWiFi evidence
- [ ] FortiAuthenticator evidence
- [ ] FortiNAC evidence
- [ ] FortiAP or FortiSwitch evidence
- [ ] FortiDeceptor/FDD evidence
- [ ] FortiWAN evidence
- [ ] PAN-OS evidence
- [ ] GlobalProtect evidence
- [ ] Panorama evidence
- [ ] HA drill notes
- [ ] Performance and soak summaries
- [ ] Security review notes
- [ ] Release notes with exact product and firmware scope
