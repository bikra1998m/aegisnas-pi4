# NAS-0066 Release Certification Checklist

This checklist contains only external validation and release evidence for the
Meraki, UniFi, and OpenWiFi cloud-controller pack. It does not block NAS-0066
engineering completion after software, tests, docs, automation, and CI are
complete.

## Software Evidence

- [x] Pinned FreeRADIUS 3.2.8 registry rows are parsed for Meraki and OpenWiFi.
- [x] AegisNAS runtime UBNT rate rows are explicitly scoped as UniFi
  compatibility extensions.
- [x] NAS-0066 report validates all 7 cloud-controller rows with zero software
  blockers.
- [x] Meraki product scopes cover MR telemetry, Dashboard SSID reconciliation,
  group policy, splash, Systems Manager posture, switch, appliance, VPN, and RF
  certification boundaries.
- [x] UniFi product scopes cover UBNT rate VSAs, UniFi Network WiFi broadcast
  reconciliation, gateway, switch, and hotspot certification boundaries.
- [x] OpenWiFi product scopes cover RADIUS AP identity and OWGW/uCentral
  certification boundaries.
- [x] Inbound parser, outbound UBNT renderer, typed evidence, controller
  adapter scope, API, UI, database evidence, OpenAPI, RBAC, readiness, support
  bundle, Makefile, and CI wiring are complete.

## External Certification

- [ ] Record `/api/v1/system/cloud-controller-pack/record` evidence for the
  release candidate.
- [ ] Export a support bundle containing `api/cloud-controller-pack.json`.
- [ ] Export a support bundle containing
  `api/cloud-controller-pack-history.json`.
- [ ] Run FreeRADIUS interoperability on the production Linux package with the
  generated dictionary/profile set.
- [ ] Validate Meraki MR accounting packets for device name, network name, AP
  name, and AP tags on supported firmware.
- [ ] Validate Meraki Dashboard SSID reconciliation against supported
  organizations, networks, and firmware.
- [ ] Validate Meraki group policy, splash, Systems Manager posture, switch,
  security appliance, VPN, and RF behavior before publishing any claim for
  those product scopes.
- [ ] Validate UniFi UBNT rate attributes against supported UniFi Network and
  AP firmware versions.
- [ ] Validate UniFi Network WiFi broadcast reconciliation against supported
  controller versions.
- [ ] Validate UniFi gateway, switch, and hotspot behavior before publishing
  any claim for those product scopes.
- [ ] Validate OpenWiFi AP MAC accounting identity from supported AP and OWGW
  releases.
- [ ] Validate OpenWiFi uCentral device configuration reconciliation by serial
  number and venue UUID.
- [ ] Capture Access-Accept, Accounting, CoA, Disconnect, and negative packet
  traces for every supported product scope.
- [ ] Run HA failover drills while preserving certification event history and
  controller sync state.
- [ ] Run performance and soak tests for expected auth/accounting/controller
  sync load.
- [ ] Complete security review for cloud API token references, redaction, logs,
  support bundles, API output, and controller error handling.
- [ ] Complete customer or lab acceptance for the exact vendor, product,
  firmware, topology, controller, subscription, and tenant scope claimed in
  release notes.

## Release Artifacts

- [ ] Certification report JSON
- [ ] Support bundle archive
- [ ] FreeRADIUS validation output
- [ ] Packet captures
- [ ] Meraki MR evidence
- [ ] Meraki Dashboard evidence
- [ ] UniFi UBNT rate VSA evidence
- [ ] UniFi Network controller evidence
- [ ] OpenWiFi AP identity evidence
- [ ] OpenWiFi OWGW/uCentral evidence
- [ ] HA drill notes
- [ ] Performance and soak summaries
- [ ] Security review notes
- [ ] Release notes with exact product, firmware, controller, and cloud scope
