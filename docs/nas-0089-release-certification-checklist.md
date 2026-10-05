# NAS-0089 Release Certification Checklist

NAS-0089 software implementation is complete when automated development tests
pass. The following items are external certification, deployment, or
environment-specific validation and do not block engineering completion.

## External Certification / Deployment

- Obtain target switch, OLT, BNG, and DHCP relay vendor firmware matrix and
  exact model scope.
- Validate compiled DHCP security evidence against FreeRADIUS on production
  Linux.
- Capture DHCP Discover, Offer, Request, ACK, NAK, Renew, Rebind, and Release
  packets with and without Option 82.
- Verify relay-agent insertion of `Agent-Circuit-Id` and `Agent-Remote-Id`
  against Cisco, Juniper/ERX, Huawei/H3C, Nokia/Alcatel, Calix, Adtran, and any
  customer-required access-node vendor.
- Verify trusted uplink handling and untrusted subscriber-port behavior on real
  switch or OLT hardware.
- Verify DHCP snooping table creation, refresh, expiry, and recovery.
- Verify IP source guard blocks unknown IP/MAC/port traffic after DHCP lease
  expiry or spoofing.
- Verify IPv6 source guard or DHCPv6 guard behavior where the target vendor
  supports it.
- Verify RADIUS accounting correlation for `Class`, `NAS-Port-Id`, and
  `Calling-Station-Id`.
- Exercise CoA or Disconnect recovery after a source-guard violation.
- Exercise failure paths for missing Option 82, mismatched circuit ID, unknown
  binding, duplicate lease, relay outage, and DHCP server outage.
- Run HA failover while DHCP security binding rows and event history are active.
- Run scale and performance benchmarking at the published port, binding, relay,
  and lease targets.
- Run long-duration DHCP churn soak with renewals, rebinds, release, replay,
  relay failure, and access-node reboot events.
- Complete security review for operator RBAC, support bundle redaction, tenant
  isolation, source-guard fail-closed behavior, and spoofing resistance.
- Complete production deployment runbook and rollback drill.
- Record customer or release-lab acceptance evidence.

## Evidence To Attach

- FreeRADIUS configuration validation output
- packet captures for DHCP relay, Option 82, accounting, CoA, and Disconnect
- switch, OLT, or BNG CLI/API exports showing DHCP snooping and source guard
  state
- DHCP server lease database correlation proof
- support bundle with NAS-0089 API captures
- production readiness report showing `broadband_dhcp_security`
- HA failover logs
- performance and soak reports
- security review notes
- signed operator acceptance record
