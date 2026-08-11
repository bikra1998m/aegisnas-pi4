# NAS-0050 Release Certification Checklist

NAS-0050 software engineering is complete. This checklist tracks external
certification and deployment work that must not block development of NAS-0051.

## Software Implementation

- [x] Code complete
- [x] Database migration complete
- [x] REST APIs complete
- [x] Admin UI complete
- [x] Configuration behavior complete
- [x] Unit tests complete
- [x] Integration tests complete
- [x] Packet/compiler tests complete
- [x] Automation and CI-ready checks complete
- [x] Documentation complete

Software Implementation: 100% Complete
Engineering Implementation: 100% Complete
Ready for External Validation: Yes

## External Certification / Deployment

- [ ] Linux nftables smoke test on Ubuntu with `aegis_runtime` table creation,
  replacement, and deletion.
- [ ] FreeRADIUS 3.2.x Linux interoperability with Access-Accept replies that
  assign `acl_policy_name`, `Filter-Id`, and quarantine behavior.
- [ ] Packet-capture proof for permitted, denied, default-dropped, established,
  invalid, quarantined, IPv4, and IPv6 flows.
- [ ] Vendor AP/switch/controller smoke tests for representative Cisco, Aruba,
  HP/ArubaOS-Switch, D-Link, Pica8, MikroTik, Fortinet, Ruckus, Juniper,
  Huawei, and H3C policy assignments.
- [ ] Controlled failure drill where nftables apply fails and previous runtime
  state plus evidence remains inspectable.
- [ ] Rollback drill from current snapshot to a previous snapshot with traffic
  verification before and after rollback.
- [ ] HA validation that runtime firewall events and snapshots replicate and
  active/standby nodes agree after failover.
- [ ] Upgrade and rollback drill from schema v54 to v55 and back with snapshot
  retention documented.
- [ ] Performance benchmark for large session counts and ACL policy sizes under
  Lite, Branch, and Enterprise hardware profiles.
- [ ] Long-duration soak test with repeated session churn, quarantine changes,
  apply, rollback, and support-bundle capture.
- [ ] Security review for RBAC, actor recording, diagnostics, nftables command
  execution, rollback evidence, and sensitive data exposure.
- [ ] Production deployment runbook execution and customer acceptance testing.

## Evidence To Attach

- `GET /api/v1/system/runtime-firewall` output before and after apply.
- `GET /api/v1/system/runtime-firewall/history` output with apply and rollback
  events.
- `nft list ruleset` output proving the active `aegis_runtime` table.
- Packet captures for allow, deny, quarantine, IPv4, IPv6, and established flow
  handling.
- Vendor model, firmware, controller version, and policy assignment matrix.
- HA failover logs and replicated database evidence.
- Performance, soak, and security review reports.
- Production deployment notes and customer acceptance record.
