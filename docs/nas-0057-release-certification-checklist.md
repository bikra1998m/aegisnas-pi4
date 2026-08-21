# NAS-0057 Release Certification Checklist

NAS-0057 software engineering is complete when the code, tests, migrations,
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
- [x] Packet/compiler tests complete
- [x] Automation and CI-ready checks complete
- [x] Documentation complete

Software Implementation: 100% Complete
Engineering Implementation: 100% Complete
Ready for External Validation: Yes

## External Certification / Deployment

- [ ] Obtain FreeRADIUS 3.2.x packet captures for AegisNAS translation VSAs 45
  through 58 with the production PEN and installed dictionary path.
- [ ] Validate Cisco `Cisco-AVPair` translation policy, public IPv4, NAT64,
  port-block, logging, and withdrawal behavior on the supported IOS / IOS-XE /
  NX-OS product scope.
- [ ] Validate Juniper `Juniper-AV-Pair` and ERX `ERX-Address-Pool-Name`
  behavior on the supported Junos or ERX firmware scope.
- [ ] Validate Huawei `Huawei-AVpair` and H3C `H3C-Av-Pair` /
  `H3C-NAT-IP-Address` behavior on the supported VRP / Comware firmware scope.
- [ ] Validate Nokia `Nokia-AVPair` behavior on the supported SR OS scope.
- [ ] Validate Starent / Cisco ASR `SN-NAT-IP-Address` and `SN-IP-Pool-Name`
  behavior on the supported StarOS scope.
- [ ] Validate Ruckus NAT pool selector behavior on the supported SmartZone or
  ZoneDirector scope.
- [ ] Validate native CGNAT, NAT44, NAT64, DS-Lite, and MAP-T dataplane adapter
  behavior for each claimed deployment target.
- [ ] Validate lawful logging retention, privacy controls, export format, and
  operator access controls with the deployment owner.

## Deployment Validation

- [ ] Prove old-version to new-version migration from schema v61 to v62.
- [ ] Prove rollback from v62 preserves pre-upgrade service state.
- [ ] Run Accounting Stop and Accounting-Off withdrawal drills for active
  translation ownership rows.
- [ ] Run CoA or reauthentication drills for public IPv4, NAT64, and port-block
  refresh paths.
- [ ] Run HA failover with active translation ownership rows and confirm standby
  status/report continuity.
- [ ] Confirm support bundles include `api/translation-policy.json` and
  `api/translation-policy-history.json`.
- [ ] Verify UI save/load behavior for translation pools, global limits, and
  role policies on the Ubuntu VM.

## Performance And Security

- [ ] Benchmark compile latency for 1, 16, 256, and 4096 translation role
  policies.
- [ ] Benchmark deterministic public IPv4 selection and port-block selection
  across small and large public pools.
- [ ] Run long-duration soak with repeated Start, Interim, Stop, CoA, and
  reauthentication updates.
- [ ] Run malformed NAT64 prefix, invalid public IPv4, overlapping pool, invalid
  port range, unknown pool, unsupported pack, and conflicting-intent packet
  tests against a lab server.
- [ ] Complete security review for translation ownership evidence, RBAC, audit
  retention, lawful logging metadata disclosure, and native dataplane adapter
  privileges.

## Release Evidence

- [ ] Attach vendor/product/firmware matrix.
- [ ] Attach FreeRADIUS packet captures and decoded attribute output.
- [ ] Attach CGNAT, NAT64, public IPv4, and port-block dataplane proof.
- [ ] Attach translation ownership history before and after withdrawal.
- [ ] Attach HA failover logs and database replication proof.
- [ ] Attach performance and soak reports.
- [ ] Attach lawful logging and privacy review report.
- [ ] Attach security review report.
- [ ] Attach customer or lab acceptance sign-off.
