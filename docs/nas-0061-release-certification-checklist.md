# NAS-0061 Release Certification Checklist

NAS-0061 software engineering is complete when code, tests, APIs, UI, database
migrations, documentation, and automation pass. The checklist below is for
external release certification only.

## External Validation

- [ ] Validate Cisco IOS/IOS-XE switch Access-Accept packets for
  `Cisco-AVPair`, `Cisco-In-ACL`, `Cisco-Out-ACL`, VLAN, route, VRF, SGT,
  voice, posture, and command-authorization behavior.
- [ ] Validate Cisco WLC/Airespace packets for WLAN ID, guest role, ACL name,
  downstream/upstream bandwidth contracts, DSCP/QoS, and firmware-specific
  acceptance.
- [ ] Validate Cisco ASA, VPN3000, and VPN5000 remote-access VPN attributes for
  group policy, split tunnel, DNS/WINS/addressing, session limits, and
  disconnect behavior.
- [ ] Validate Starent/Cisco ASR mobile-core attributes for subscriber pool,
  NAT public IPv4, charging/accounting counters, APN policy, and bearer context.
- [ ] Validate Meraki accounting context with Dashboard-managed SSIDs and exact
  network firmware/API versions.
- [ ] Run FreeRADIUS production Linux interoperability with the generated
  dictionary release profile and packet captures.
- [ ] Run RFC 5176 CoA and Disconnect acceptance against representative Cisco
  devices and controller paths.
- [ ] Capture positive, negative, malformed, duplicate, repeated, unknown, and
  oversized VSA packet traces.
- [ ] Validate HA active/standby behavior, evidence replication, rollback, and
  support bundle collection during Cisco-family changes.
- [ ] Run performance and soak tests with Cisco-family reply rendering,
  accounting ingest, and event history enabled.
- [ ] Complete independent security review for Cisco AVPair input handling,
  evidence redaction, support bundles, and operator RBAC.
- [ ] Attach customer acceptance evidence before publishing customer-certified
  claims.

## Release Gate

- [ ] The recorded `/api/v1/system/cisco-family-pack` fingerprint matches the
  release build.
- [ ] All hardware, firmware, FreeRADIUS, HA, performance, security, and
  customer evidence is signed or linked in the release record.
- [ ] Unsupported or firmware-specific behavior is documented as scoped,
  limited, or not applicable.
