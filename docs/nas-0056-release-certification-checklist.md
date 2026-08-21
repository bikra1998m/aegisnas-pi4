# NAS-0056 Release Certification Checklist

NAS-0056 software engineering is complete when the code, tests, migrations,
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

- [ ] Obtain FreeRADIUS 3.2.x packet captures for `Framed-IP-Address`,
  `Framed-IP-Netmask`, `Framed-Pool`, `Framed-IPv6-Address`,
  `Framed-IPv6-Prefix`, `Framed-IPv6-Pool`, and `Delegated-IPv6-Prefix`.
- [ ] Validate AegisNAS product VSAs 31 through 44 with the production PEN and
  installed dictionary path.
- [ ] Validate Cisco address, DHCPv6, RA, and delegated-prefix AVPair behavior
  on the supported IOS / IOS-XE / NX-OS product scope.
- [ ] Validate Juniper / ERX address pool and delegated-prefix behavior on the
  supported Junos or ERX firmware scope.
- [ ] Validate Huawei and H3C address, pool, DHCPv6, RA, and delegated-prefix
  behavior on the supported VRP / Comware firmware scope.
- [ ] Validate MikroTik `Mikrotik-Delegated-IPv6-Pool` behavior on the supported
  RouterOS release.
- [ ] Validate Nokia / Alcatel-Lucent service-router address and delegated
  prefix AVPair behavior on the supported SR OS scope.
- [ ] Validate standards-only dual-stack assignment against a NAS that consumes
  only RFC attributes.
- [ ] Validate native DHCPv6 daemon, relay, and prefix delegation behavior for
  the selected deployment adapter.
- [ ] Validate router advertisement packet emission, RA flags, RDNSS, DNSSL,
  and SLAAC behavior on the selected deployment adapter.

## Deployment Validation

- [ ] Prove old-version to new-version migration from schema v60 to v61.
- [ ] Prove rollback from v61 preserves pre-upgrade service state.
- [ ] Run Accounting Stop and Accounting-Off withdrawal drills.
- [ ] Run CoA or reauthentication drills for address and prefix refresh paths.
- [ ] Run HA failover with active address ownership rows and confirm standby
  status/report continuity.
- [ ] Confirm support bundles include `api/address-policy.json` and
  `api/address-policy-history.json`.
- [ ] Verify UI save/load behavior for pools, DHCPv6 defaults, RA defaults, and
  role policies on the Ubuntu VM.

## Performance And Security

- [ ] Benchmark compile latency for 1, 16, 128, and 1024 address role policies.
- [ ] Benchmark deterministic pool selection for large IPv4, IPv6, delegated
  prefix, and RA prefix pools.
- [ ] Run long-duration soak with repeated Start, Interim, Stop, CoA, and
  reauthentication updates.
- [ ] Run malformed address, invalid prefix, overlapping pool, unknown pool,
  unsupported pack, and conflicting-assignment packet tests against a lab
  server.
- [ ] Complete security review for address ownership evidence, RBAC, audit
  retention, address metadata disclosure, and native DHCPv6/RA adapter
  privileges.

## Release Evidence

- [ ] Attach vendor/product/firmware matrix.
- [ ] Attach FreeRADIUS packet captures and decoded attribute output.
- [ ] Attach DHCPv6 and RA packet captures where native adapters are claimed.
- [ ] Attach address and prefix ownership history before and after withdrawal.
- [ ] Attach HA failover logs and database replication proof.
- [ ] Attach performance and soak reports.
- [ ] Attach security review report.
- [ ] Attach customer or lab acceptance sign-off.
