# NAS-0058 Release Certification Checklist

NAS-0058 software engineering is complete when the code, tests, migrations,
APIs, UI, documentation, and CI pass. The items below require external systems
or production-like environments and do not keep the roadmap item open.

## Software Implementation

- [x] Code complete
- [x] Database migration complete
- [x] REST APIs complete
- [x] Admin UI complete
- [x] Configuration behavior complete
- [x] Unit tests complete
- [x] Integration tests complete
- [x] Packet and transaction tests complete
- [x] Automation and CI-ready checks complete
- [x] Documentation complete

Software Implementation: 100% Complete
Engineering Implementation: 100% Complete
Ready for External Validation: Yes

## External Certification / Deployment

- [ ] Validate atomic apply on Ubuntu with real `ip`, `tc`, `nft`, and hostapd
  VLAN file targets.
- [ ] Validate controller-sync participation against Cisco, Aruba, UniFi,
  Ruckus, Fortinet, Mist, and other claimed controller adapters.
- [ ] Capture FreeRADIUS Access-Accept, CoA, Disconnect, Accounting Start,
  Interim, Stop, and Accounting-Off flows before and after atomic apply.
- [ ] Validate vendor hardware behavior for VLAN, QoS, ACL/firewall, route,
  address, translation, and controller drift after atomic apply.
- [ ] Validate HA active/standby behavior while an apply, compensation, drift,
  or rollback operation is active.
- [ ] Run split-brain and standby-promotion drills with open transaction
  history.
- [ ] Validate old-version to schema v63 migration and v63 rollback package
  restore on the Ubuntu VM.
- [ ] Run performance benchmarks with 1, 16, 256, and 4096 active sessions and
  full VLAN/QoS/firewall participants.
- [ ] Run long-duration soak with repeated preview, apply, drift, compensation,
  rollback, controller outage, and HA failover cycles.
- [ ] Complete security review for RBAC, audit evidence, transaction JSON,
  sensitive data handling, command execution boundaries, and support bundles.

## Release Evidence

- [ ] Attach transaction history export with successful preview, apply, drift,
  compensation, and rollback examples.
- [ ] Attach support bundle containing
  `api/enforcement-transactions.json` and
  `api/enforcement-transactions-history.json`.
- [ ] Attach packet captures and decoded FreeRADIUS output.
- [ ] Attach physical Linux dataplane proof for each local target.
- [ ] Attach controller product and firmware matrix.
- [ ] Attach HA failover logs and database replication proof.
- [ ] Attach performance and soak reports.
- [ ] Attach security review report.
- [ ] Attach customer or lab acceptance sign-off.
