# NAS-0070 Release Certification Checklist

NAS-0070 software implementation is complete when automated code, API, UI,
configuration, packet, and documentation work passes. The items below are
external release gates and do not block engineering completion.

## External Validation

- [ ] Validate the generated AegisNAS dictionary and MikroTik VSA names against
  FreeRADIUS on the target Linux release.
- [ ] Capture Access-Accept packets containing `Mikrotik-Rate-Limit`,
  `Mikrotik-Group`, `Mikrotik-Address-List`, `Mikrotik-Switching-Filter`,
  `Mikrotik-Total-Limit`, `Mikrotik-Total-Limit-Gigawords`,
  `Mikrotik-Advertise-URL`, `Mikrotik-Host-IP`,
  `Mikrotik-Delegated-IPv6-Pool`, and CAPsMAN VLAN attributes.
- [ ] Capture accounting packets for receive, transmit, total, gigawords,
  wireless posture, signal, DHCP option, and tenant evidence.
- [ ] Validate RouterOS 6.x and 7.x behavior for PPP, PPPoE, hotspot, simple
  queues, firewall address lists, switching filters, DHCP option sets, IPv4
  host assignment, IPv6 delegated pools, and CAPsMAN wireless profiles.
- [ ] Validate RFC 5176 CoA and Disconnect workflows, including ACK, NAK,
  timeout, retry, idempotency, and rollback behavior.
- [ ] Validate RouterOS REST reconciliation against a lab router with HTTPS and
  dedicated credentials.
- [ ] Validate HA failover with active/standby nodes while RouterOS sessions,
  accounting, and dynamic authorization requests are in flight.
- [ ] Run scale and performance benchmarks on lite, branch, enterprise, and
  high-spec hardware profiles.
- [ ] Run long-duration soak tests covering reauthentication, accounting
  rollover, quota high-word rollover, and controller sync retries.
- [ ] Complete an external security review for secret redaction, support-bundle
  output, audit history, RouterOS API credentials, and RADIUS shared secrets.
- [ ] Attach firmware versions, router model, packet captures, logs, test run
  IDs, operator approvals, and customer acceptance evidence to the release
  record.

## Release Claim Rules

- Software-ready claims may reference `mikrotik_pack` readiness and
  `mikrotik_pack_events` evidence.
- Hardware-certified claims require completed RouterOS packet captures and
  firmware-scoped evidence.
- CAPsMAN-certified claims require real CAPsMAN provisioning and client roam
  validation.
- PPP/PPPoE and hotspot claims require live subscriber session proof.
- CoA/Disconnect claims require live ACK/NAK evidence from the target RouterOS
  release.
