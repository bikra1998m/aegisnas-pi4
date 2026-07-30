# NAS-0032 Release Certification Checklist

NAS-0032 software engineering is complete when the committed code, automated
tests, migrations, APIs, UI, and documentation pass. The items below require
real hardware, third-party software, production-like deployment, or long-running
validation and do not block closing the engineering feature.

## External Certification / Deployment

- [ ] FreeRADIUS interoperability smoke test on the supported Ubuntu release
  with `dictionary.aegisnas` installed and `AegisNAS-Service-Chain` /
  `AegisNAS-Service-Name` rendered in reply output.
- [ ] Packet capture validation for Access-Accept replies containing standard
  attributes, AegisNAS service-chain VSAs, and selected vendor-pack attributes.
- [ ] Juniper ERX/Junos subscriber-service smoke test for role, data service,
  QoS, ACL/filter, reauthorization, and rollback behavior.
- [ ] Huawei BRAS/BNG smoke test for service/QoS/ACL intent acceptance and
  accounting continuity.
- [ ] H3C BRAS/BNG smoke test for service/QoS/ACL intent acceptance and
  accounting continuity.
- [ ] Nokia SR OS / Alcatel-Lucent service-router smoke test for service name,
  profile, QoS, subscriber accounting, and rollback evidence.
- [ ] Starent or equivalent mobile/subscriber platform smoke test for
  subscriber service activation and accounting evidence.
- [ ] WLAN controller/AP smoke test for service-chain replies used as
  enterprise access-policy hints.
- [ ] Controlled failure drill: invalid optional service, required service
  failure, rollback, repeated rollback idempotency, and accounting stop checks.
- [ ] HA drill: activate on active node, replicate evidence, fail over, then
  roll back from the new active node.
- [ ] Upgrade drill from the previous release with existing `policy_rules` and
  `policy_simulation_analyses`, confirming v37 migration repair and rollback.
- [ ] Performance benchmark for policy evaluation and activation evidence at
  lite, branch, and enterprise chain limits.
- [ ] Long-duration soak with accounting-start rows, rollback events, support
  bundle capture, and production readiness polling.
- [ ] Security review of tenant isolation, RBAC, hashed identity evidence,
  service-chain JSON bounds, and audit log coverage.

## Release Sign-Off Evidence

- [ ] Test date, build SHA, appliance profile, OS image, and schema version.
- [ ] Device vendor, product, firmware, dictionary release, and enabled packs.
- [ ] Captured RADIUS packets and sanitized reply attribute transcript.
- [ ] API transcript for preview, activate, report, rollback, and support bundle.
- [ ] HA replication transcript and failover timeline.
- [ ] Benchmark and soak results with CPU, memory, DB size, and latency.
- [ ] Known limitations and vendor/product scope approved for release notes.
