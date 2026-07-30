# NAS-0033 Release Certification Checklist

Feature: Command authorization and TACACS+

Software implementation is complete when code, schema, APIs, UI, tests,
automation, and documentation are committed. The items below require external
devices, production-like Linux hosts, third-party environments, or release
sign-off evidence.

## External Certification / Deployment

- [ ] Register packet captures for RFC 8907 authentication, authorization, and
  accounting against production Linux.
- [ ] Verify encrypted TACACS+ packet interop with Cisco IOS XE/NX-OS command
  authorization and accounting.
- [ ] Verify Juniper Junos login class and command authorization behavior.
- [ ] Verify HPE/ArubaOS-Switch privilege behavior and accounting records.
- [ ] Verify Dell/Force10, Brocade/ICX/FastIron, Extreme EXOS/VOSS, and Arista
  EOS command authorization smoke tests.
- [ ] Confirm monitor-mode migration behavior permits device commands while
  recording deny decisions.
- [ ] Confirm enforce-mode deny prevents blocked commands on real devices.
- [ ] Run controlled shared-secret mismatch, unknown client, disabled client,
  malformed packet, oversized packet, and replay-style negative tests.
- [ ] Validate TACACS+ traffic through active/standby and database failover
  drills.
- [ ] Run long-duration accounting and authorization soak with command volume
  representative of production switch fleets.
- [ ] Benchmark concurrent TCP sessions on lite, branch, and enterprise
  hardware profiles.
- [ ] Archive support bundles containing TACACS+ status, authorization evidence,
  accounting records, runtime status, and sanitized config.
- [ ] Complete customer acceptance testing for least-privilege command sets,
  break-glass roles, and rollback from monitor to enforce.

