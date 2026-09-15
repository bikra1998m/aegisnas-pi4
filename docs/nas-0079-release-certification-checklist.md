# NAS-0079 Release Certification Checklist

Feature: RF, RRM, mesh, and radio planning

Software Implementation: 100% Complete
Engineering Implementation: 100% Complete
Ready for External Validation: Yes

## External Certification / Deployment

- [ ] Validate RF planning against Cisco controller/AP firmware and API
  versions in the release matrix.
- [ ] Validate RF planning against Aruba/HPE, Ruckus, Extreme, Meraki, UniFi,
  Cambium, Juniper Mist, Fortinet, MikroTik, OpenWiFi, and hostapd versions in
  scope.
- [ ] Capture pre-change and post-change RF survey data for supported bands,
  channel width, power, DFS, and regulatory domain claims.
- [ ] Capture AP/controller telemetry proving planned channel and power state.
- [ ] Capture spectrum/interference evidence for dense-channel and warning
  scenarios.
- [ ] Validate mesh root, mesh leaf, backhaul SSID, bridge VLAN, hop limit,
  backhaul RSSI, and recovery behavior on real AP hardware.
- [ ] Validate client steering, BSS transition, sticky-client thresholds, and
  load-balancing behavior with representative clients.
- [ ] Validate interaction with 802.11r/k/v roaming, Passpoint, PPSK, dynamic
  VLAN, CoA, and accounting flows.
- [ ] Execute controller API outage, authentication failure, rate-limit, partial
  response, and drift drills.
- [ ] Execute HA failover while RF preview/apply/history and runtime status are
  active.
- [ ] Execute upgrade and rollback drills preserving RF lifecycle history and
  plan fingerprints.
- [ ] Run scale benchmarks for the largest supported AP/radio estate.
- [ ] Run long-duration soak testing for RRM recalculation, mesh stability,
  steering events, accounting correlation, and support bundle generation.
- [ ] Complete security audit for controller credentials, logs, support bundles,
  UI rendering, and exported evidence.
- [ ] Complete production deployment and customer acceptance evidence for exact
  AP/controller/client/firmware scope.

These activities are required for release certification and customer claims, but
they do not keep NAS-0079 engineering open.
