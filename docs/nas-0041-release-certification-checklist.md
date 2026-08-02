# NAS-0041 Release Certification Checklist

Software engineering for NAS-0041 is complete when the automated tests, docs,
UI, API, schema, and CI target pass. The following items require external
systems, real hardware, production-like deployments, or independent review and
do not block closing the development feature.

## External Certification / Deployment

- [ ] Run FreeRADIUS accounting interoperability on production Linux with local
  SQL accounting, ingest spool, ordering, counters, service correlation, and
  charging enabled.
- [ ] Capture packet traces for `Start`, `Interim-Update`, `Stop`, duplicate,
  delayed, retransmitted, malformed, and late-correction accounting packets.
- [ ] Validate Cisco, Juniper, Huawei, Nokia/Alcatel, Ericsson, MikroTik,
  Cambium, WLAN controller, VPN, hotspot, BNG/BRAS, and mobile-core accounting
  records against the CDR projection.
- [ ] Validate 3GPP, 3GPP2, Starent/Cisco, and Ericsson charging-field
  correlation in a telecom lab before making mobile-core charging claims.
- [ ] Validate exported JSON Lines, JSON, and CSV payloads with the downstream
  billing or mediation system.
- [ ] Validate payload SHA-256, manifest SHA-256, and previous-manifest hash
  chain verification with external audit tooling.
- [ ] Run correction, rollback, replay, and failover drills and confirm CDRs are
  not double charged and late corrections return to pending export.
- [ ] Validate PostgreSQL HA behavior for concurrent reconcile/export attempts,
  standby promotion, and export membership integrity.
- [ ] Run performance benchmarks for peak accounting packet rate, reconcile
  batch size, rating throughput, export size, and API/report latency on lite,
  branch, and enterprise hardware profiles.
- [ ] Run long-duration soak tests with interim accounting enabled and confirm
  no CDR drift, queue loss, hash mismatch, or retention regression.
- [ ] Run security review for RBAC, audit events, identity hashing, export
  privacy, support-bundle redaction, and billing data retention.
- [ ] Confirm support bundles include `api/accounting-charging.json` and do not
  include raw usernames, station IDs, secrets, or raw packet payloads.
- [ ] Capture customer acceptance evidence for billing reconciliation,
  retention, export download, incident response, and rollback procedures.

## Release Sign-Off Evidence

- [ ] Production Linux FreeRADIUS configuration and version recorded.
- [ ] Device/product/firmware matrix recorded.
- [ ] Packet captures archived with redaction notes.
- [ ] Billing or mediation import/export acceptance report archived.
- [ ] Export hash-chain verification report archived.
- [ ] HA drill logs and runtime status snapshots archived.
- [ ] Performance and soak reports archived.
- [ ] Security review outcome archived.
- [ ] Customer or lab acceptance record archived.
