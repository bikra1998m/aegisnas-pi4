# NAS-0064 Release Certification Checklist

This checklist contains only external validation and release evidence for the
Ruckus and ICX pack. It does not block NAS-0064 engineering completion after
software, tests, docs, automation, and CI are complete.

## Software Evidence

- [x] Pinned FreeRADIUS 3.2.8 registry rows are parsed for Ruckus and Foundry.
- [x] NAS-0064 report validates all 97 pinned dictionary rows with zero software
  blockers.
- [x] Foundry rows are tracked as Ruckus ICX/FastIron product scope without
  moving Dell, Brocade, Arista, or generic switching claims out of NAS-0071.
- [x] Inbound parser, outbound renderer, typed pass-through, FlexAuth grammar,
  DPSK/subscriber redaction, API, UI, database evidence, OpenAPI, RBAC,
  readiness, support bundle, Makefile, and CI wiring are complete.

## External Certification

- [ ] Record `/api/v1/system/ruckus-icx-pack/record` evidence for the release
  candidate.
- [ ] Export a support bundle containing `api/ruckus-icx-pack.json`.
- [ ] Export a support bundle containing `api/ruckus-icx-pack-history.json`.
- [ ] Run FreeRADIUS interoperability on the production Linux package with the
  generated dictionary/profile set.
- [ ] Validate Ruckus SmartZone role groups, VLAN, VLAN pool, WLAN name, SSID,
  WISPr redirect policy, guest portal token, QoS, quota, DPSK/PPSK redaction
  behavior, zone, cluster, domain, SCI role, and SCI resource group handling on
  supported product and firmware versions.
- [ ] Validate Ruckus ZoneDirector role, VLAN, portal, accounting, WLAN, and
  roaming context handling on supported product and firmware versions.
- [ ] Validate Ruckus Unleashed and Ruckus One enterprise WLAN policy behavior
  for the exact controller/API versions claimed in release notes.
- [ ] Validate ICX/FastIron administrative login, command authorization,
  privilege level, command exception, access-list, MAC authentication, 802.1X
  lookup, MAC-based VLAN/QoS, CoA command, service role, role template, and voice
  phone policy behavior on supported switch and firmware versions.
- [ ] Capture Access-Accept, Accounting, CoA, Disconnect, and negative packet
  traces for every supported product scope.
- [ ] Run HA failover drills while preserving certification event history and
  controller sync state.
- [ ] Run performance and soak tests for expected auth/accounting/CoA load.
- [ ] Complete security review for DPSK/subscriber redaction, logs, support
  bundles, API output, credential references, and controller tokens.
- [ ] Complete customer or lab acceptance for the exact vendor, product,
  firmware, topology, and controller versions claimed in release notes.

## Release Artifacts

- [ ] Certification report JSON
- [ ] Support bundle archive
- [ ] FreeRADIUS validation output
- [ ] Packet captures
- [ ] Ruckus SmartZone evidence
- [ ] Ruckus ZoneDirector evidence
- [ ] Ruckus Unleashed evidence
- [ ] Ruckus One evidence
- [ ] ICX/FastIron evidence
- [ ] HA drill notes
- [ ] Performance and soak summaries
- [ ] Security review notes
- [ ] Release notes with exact product and firmware scope
