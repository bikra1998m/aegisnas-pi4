# NAS-0063 Release Certification Checklist

This checklist contains only external validation and release evidence for the
Juniper, ERX, Extreme, and Mist pack. It does not block NAS-0063 engineering
completion after software, tests, docs, automation, and CI are complete.

## Software Evidence

- [x] Pinned FreeRADIUS 3.2.8 registry rows are parsed for Juniper, ERX, and
  Extreme.
- [x] NAS-0063 report validates all 260 pinned dictionary rows with zero
  software blockers.
- [x] Mist is tracked as Juniper controller/product scope without inventing a
  separate FreeRADIUS dictionary namespace.
- [x] Inbound parser, outbound renderer, typed pass-through, secret redaction,
  API, UI, database evidence, OpenAPI, RBAC, readiness, support bundle, Makefile,
  and CI wiring are complete.

## External Certification

- [ ] Record `/api/v1/system/juniper-extreme-pack/record` evidence for the
  release candidate.
- [ ] Export a support bundle containing `api/juniper-extreme-pack.json`.
- [ ] Export a support bundle containing `api/juniper-extreme-pack-history.json`.
- [ ] Run FreeRADIUS interoperability on the production Linux package with the
  generated dictionary/profile set.
- [ ] Validate Junos administrative login, command authorization, firewall
  filter, VLAN, CWA redirect, CoS, and DHCP evidence behavior on supported
  Juniper product/firmware versions.
- [ ] Validate ERX/E-Series virtual router, pool, PPPoE, IPv6 delegated-pool,
  service activation, PCEF, QoS, accounting, and bulk CoA behavior on supported
  product/firmware versions.
- [ ] Validate ExtremeXOS/Switch Engine CLI authorization, netlogin VLAN,
  extended VLAN, portal hints, security profile, user location, and VM context
  behavior on supported product/firmware versions.
- [ ] Validate Juniper Mist pull, preview, push, drift, and enterprise WLAN
  behavior using the target regional Mist API and site UUID.
- [ ] Capture Access-Accept, Accounting, CoA, Disconnect, and negative packet
  traces for every supported product scope.
- [ ] Run HA failover drills while preserving certification event history and
  controller sync state.
- [ ] Run performance and soak tests for expected auth/accounting/CoA load.
- [ ] Complete security review for redaction, logs, support bundles, API output,
  credential references, and controller tokens.
- [ ] Complete customer or lab acceptance for the exact vendor, product,
  firmware, topology, and controller versions claimed in release notes.

## Release Artifacts

- [ ] Certification report JSON
- [ ] Support bundle archive
- [ ] FreeRADIUS validation output
- [ ] Packet captures
- [ ] Juniper/Junos evidence
- [ ] ERX/E-Series evidence
- [ ] Extreme evidence
- [ ] Mist controller evidence
- [ ] HA drill notes
- [ ] Performance and soak summaries
- [ ] Security review notes
- [ ] Release notes with exact product and firmware scope
