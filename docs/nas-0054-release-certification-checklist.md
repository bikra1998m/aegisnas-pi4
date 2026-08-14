# NAS-0054 Release Certification Checklist

NAS-0054 engineering implementation is complete when software, tests,
automation, UI, API, configuration, and documentation are complete. The items
below require external organizations, production Linux hosts, real NAS devices,
customer environments, or long-running validation and do not block the next
roadmap feature.

## Software Status

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready For External Validation: Yes

## External Certification

- [ ] Confirm the production AegisNAS IANA PEN is active before using product
  VSAs outside lab or pilot environments.
- [ ] Install `dictionary.aegisnas` on a production FreeRADIUS 3.2.x Linux
  host and validate `radiusd -XC`.
- [ ] Capture Access-Accept packets for data VLAN, tagged voice VLAN, extra
  tagged VLANs, pool selection, fallback VLAN, auth-fail VLAN, and QinQ intent.
- [ ] Validate RFC 2868 tunnel attributes against at least one standards-based
  AP or switch.
- [ ] Validate RFC 4675 `Egress-VLANID` tagged and untagged behavior against
  HP/ArubaOS-Switch or compatible devices.
- [ ] Validate `Extreme-Netlogin-Extended-Vlan` against certified Extreme
  Switch Engine firmware.
- [ ] Validate AegisNAS product VSAs with a FreeRADIUS client, packet capture,
  and broker parse evidence.
- [ ] Validate MAB endpoint generation for approved and quarantined endpoints.
- [ ] Validate local dynamic VLAN lifecycle alignment with NAS-0053 on Ubuntu
  VM and physical Linux hosts.
- [ ] Run controller smoke tests for AP/switch families that consume VLAN
  authorization through their controller.
- [ ] Perform HA active/standby replay with matching `vlan_policy_events`
  evidence after failover.
- [ ] Run upgrade and rollback tests from the previous schema version to schema
  version 59.
- [ ] Run malformed packet and unsupported attribute tests with packet capture
  evidence.
- [ ] Benchmark compiler latency with large role and pool catalogs.
- [ ] Complete 24-hour soak with authentication, MAB, VLAN pool churn, and
  status polling.
- [ ] Complete security review for tenant scoping, RBAC, evidence retention,
  and redaction.
- [ ] Attach device model, firmware, FreeRADIUS version, OS version, packet
  captures, and operator sign-off to the release evidence bundle.
