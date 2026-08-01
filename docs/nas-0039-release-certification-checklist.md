# NAS-0039 Release Certification Checklist

NAS-0039 software engineering is complete when code, schema, APIs, UI,
automation, docs, and automated tests pass. The following activities require
external systems, physical hardware, customer environments, or long-running labs
and do not block engineering completion.

## External Certification / Deployment

- [ ] Import production FreeRADIUS `radacct` rows on Linux and confirm
  `acctmultisessionid`, `acctlinkcount`, service fields, and AegisNAS
  correlation fields reconcile.
- [ ] Capture BNG/BRAS accounting packets with parent subscriber sessions,
  service legs, and multi-link PPP accounting.
- [ ] Capture mobile packet-core or gateway accounting with APN, bearer, and
  roaming identifiers.
- [ ] Capture voice/SBC or VPN accounting packets with call-leg or tunnel-leg
  identifiers.
- [ ] Validate Juniper ERX, Nokia SR, Huawei, Starent/Cisco ASR, Ericsson,
  BroadSoft, Acme Packet, Cisco voice/VPN, and representative generic NAS
  samples against `/api/v1/system/accounting-services`.
- [ ] Run subscriber service-chain activation tests and confirm service-level
  accounting rows receive Start, Interim, Stop, counters, and closure state.
- [ ] Run controlled conflict drills where the same child session is claimed by
  two parent sessions and confirm readiness degrades with clear evidence.
- [ ] Run Stop and Accounting-Off closure drills and confirm active service-leg
  rows close without losing historical evidence.
- [ ] Run HA failover with accounting replay and verify service correlations
  remain consistent on the promoted node.
- [ ] Run performance benchmarks with high-frequency Interim-Update traffic and
  many child service legs per parent session.
- [ ] Run long-duration soak tests covering service churn, bearer churn,
  multi-link churn, and accounting replay.
- [ ] Complete security review for Class metadata parsing, hashed identity
  storage, conflict details, and support-bundle exposure.
- [ ] Complete customer acceptance testing for BNG/mobile/voice/VPN operational
  investigations.

## Evidence To Archive

- `/api/v1/system/accounting-services`
- `/api/v1/system/sql-accounting`
- `/api/v1/system/accounting-ordering`
- `/api/v1/system/accounting-counters`
- `/api/v1/system/accounting-ip`
- `/api/v1/system/production-readiness`
- support bundle containing `api/accounting-services.json`
- FreeRADIUS SQL import logs
- packet captures with secrets and subscriber identifiers redacted
- subscriber service-chain activation and rollback notes
- HA failover drill notes
- performance and soak results
