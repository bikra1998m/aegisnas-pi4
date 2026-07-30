# NAS-0038 Release Certification Checklist

NAS-0038 software engineering is complete when code, schema, APIs, UI,
automation, docs, and automated tests pass. The following activities require
external systems, physical hardware, customer environments, or long-running labs
and do not block engineering completion.

## External Certification / Deployment

- [ ] Import production FreeRADIUS `radacct` rows on Linux and confirm
  `framedroute`, `framedipv6route`, and delegated-prefix fields reconcile.
- [ ] Capture Access-Request and Accounting-Request packets from at least one
  dual-stack enterprise AP or controller.
- [ ] Capture BNG/BRAS accounting packets with `Delegated-IPv6-Prefix` and
  framed IPv4/IPv6 route attributes.
- [ ] Validate Cisco, Juniper ERX, Huawei, Nokia, MikroTik, and Fortinet packet
  samples against `/api/v1/system/accounting-ip`.
- [ ] Run controlled invalid-prefix and invalid-route drills and confirm
  readiness degrades with clear evidence.
- [ ] Run Stop and Accounting-Off closure drills and confirm active assignments
  close without losing historical rows.
- [ ] Run HA failover with accounting replay and verify assignment state remains
  consistent on the promoted node.
- [ ] Run performance benchmarks with high-frequency Interim-Update traffic and
  long route lists.
- [ ] Run long-duration soak tests covering lease churn, delegated-prefix churn,
  and accounting replay.
- [ ] Complete security review for route text handling and support-bundle
  exposure.
- [ ] Complete customer acceptance testing for dual-stack audit and subscriber
  attribution workflows.

## Evidence To Archive

- `/api/v1/system/accounting-ip`
- `/api/v1/system/sql-accounting`
- `/api/v1/system/accounting-ordering`
- `/api/v1/system/production-readiness`
- support bundle containing `api/accounting-ip.json`
- FreeRADIUS SQL import logs
- packet captures with secrets redacted
- HA failover drill notes
- performance and soak results
