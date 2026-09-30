# NAS-0083 Release Certification Checklist

Engineering implementation for NAS-0083 is complete when automated software
tests, API/UI evidence, docs, and CI pass. The items below are external
certification, deployment, or customer-environment activities and do not block
software roadmap closure.

## Software Completion Evidence

- [x] Configuration schema and validation for `broadband.subscriber_state`.
- [x] Canonical broadband subscriber state machine and transition tests.
- [x] Product, service-leg, failure, reconnect, accounting, and compliance
  report generation.
- [x] Durable schema and event-ledger migration.
- [x] Preview/apply/history admin APIs with RBAC, OpenAPI, support bundle,
  system status, production readiness, and runtime status.
- [x] Access Settings UI preview/apply workflow and browser mock coverage.
- [x] Example config, API docs, operations guide, roadmap, backlog, Makefile,
  and CI coverage.

## External Certification / Deployment

- [ ] IANA PEN and production dictionary identity are used in release builds.
- [ ] FreeRADIUS production Linux interoperability captures are attached.
- [ ] PPPoE and IPoE subscriber lifecycle packet captures are attached.
- [ ] Juniper ERX/E-Series, Huawei BRAS/BNG, H3C, Nokia/Alcatel-Lucent SR OS,
  ZTE, Ericsson/Redback, Calix, Adtran, MikroTik, and other scoped BNG firmware
  versions are tested or explicitly waived.
- [ ] Accounting Start, Interim-Update, Stop, Accounting-Off, duplicate,
  out-of-order, and stale-session recovery drills are signed off.
- [ ] Address, route, QoS, NAT, CoA, quota, charging, and service-chain
  transitions are validated on scoped devices.
- [ ] Reconnect recovery, forced disconnect, quota suspension, accounting gap,
  NAS restart, and stale ownership failure drills are signed off.
- [ ] HA active/standby failover and split-brain recovery are validated with
  subscriber sessions active.
- [ ] Performance benchmarks cover target Lite, Branch, and Enterprise hardware
  classes.
- [ ] Long-duration soak testing covers session churn, accounting load, CoA
  bursts, reconnect storms, and support-bundle export.
- [ ] Security review covers management API authorization, event retention,
  tenant isolation, sensitive attribute redaction, and failure modes.
- [ ] Customer acceptance testing is complete for the release deployment scope.

## Release Gate

Ship only when every external certification item is checked or has a documented
waiver with vendor, product, firmware, topology, risk owner, expiry date, and
rollback plan.
