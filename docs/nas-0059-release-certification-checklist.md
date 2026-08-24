# NAS-0059 Release Certification Checklist

NAS-0059 software engineering is complete when the code, tests, migrations,
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
- [x] Packet and route-rendering tests complete
- [x] Automation and CI-ready checks complete
- [x] Documentation complete

Software Implementation: 100% Complete
Engineering Implementation: 100% Complete
Ready for External Validation: Yes

## External Certification / Deployment

- [ ] Obtain production IANA PEN before making public vendor claims.
- [ ] Validate generated FRR artifact loading on Ubuntu with the target
  FRRouting version.
- [ ] Validate `frr-vtysh` apply against BGP, OSPF, and OSPF3 daemons.
- [ ] Capture FreeRADIUS Access-Accept, Accounting Start, Interim, Stop,
  Accounting-Off, CoA, and Disconnect flows that create, update, and withdraw
  route ownership.
- [ ] Validate route advertisements and withdrawals against Cisco, Juniper,
  Nokia, Huawei, MikroTik, and ERX-style subscriber routing environments.
- [ ] Validate route reflection, VRF scoping, route-map behavior, communities,
  metrics, MED, and local-preference with real routers or certified labs.
- [ ] Validate hardware FIB installation and withdrawal latency.
- [ ] Validate HA active/standby behavior during route export preview, apply,
  rollback, failover, and database replication.
- [ ] Validate old-version to schema v64 migration and rollback package restore
  on the Ubuntu VM.
- [ ] Run scale benchmarks at 1, 16, 256, 4096, and 100000 active route
  ownership rows.
- [ ] Run long-duration soak with route churn, Accounting Stop withdrawal,
  dampening, atomic enforcement apply, rollback, FRR restart, and HA failover.
- [ ] Complete security review for path validation, command execution,
  artifact permissions, support bundles, RBAC, and audit evidence.

## Release Evidence

- [ ] Attach subscriber route export preview, apply, rollback, and history
  exports.
- [ ] Attach support bundle containing `api/subscriber-route-export.json` and
  `api/subscriber-route-export-history.json`.
- [ ] Attach FRR running-config before and after apply.
- [ ] Attach BGP, OSPF, and OSPF3 neighbor and route-table captures.
- [ ] Attach decoded FreeRADIUS packet captures with route ownership
  attributes.
- [ ] Attach vendor/product/firmware compatibility matrix.
- [ ] Attach HA failover logs and database replication proof.
- [ ] Attach performance and soak reports.
- [ ] Attach security review report.
- [ ] Attach customer or lab acceptance sign-off.
