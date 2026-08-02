# NAS-0040 Release Certification Checklist

Software engineering for NAS-0040 is complete. The following items require
external systems, real hardware, production-like deployments, or independent
review and do not block closing the development feature.

## External Certification / Deployment

- [ ] Run FreeRADIUS accounting packet interoperability on production Linux with
  local SQL enabled and AegisNAS ingest spool enabled.
- [ ] Capture packet traces for `Start`, `Interim-Update`, `Stop`,
  retransmission, duplicate, delayed, and malformed accounting requests.
- [ ] Validate AP, switch, WLAN controller, VPN, BNG/BRAS, and hotspot devices
  against the ingest spool under transient database failures.
- [ ] Validate queue backpressure behavior with a real access-device retry
  interval and confirm no silent packet loss claims are made.
- [ ] Run controlled database outage, service restart, and node failover drills;
  confirm replay applies records and preserves duplicate/ordering/counter/IP and
  service-correlation semantics.
- [ ] Validate poison-record workflows with corrupted payload evidence and
  operator review procedures.
- [ ] Validate PostgreSQL HA behavior, lock ownership, replay continuity, and
  retention pruning on active/standby deployments.
- [ ] Run performance benchmarks for peak accounting packet rate, queue depth,
  replay batch size, and API/report latency on lite, branch, and enterprise
  hardware profiles.
- [ ] Run long-duration soak tests with interim accounting enabled and confirm
  no loss-SLO breaches under expected load.
- [ ] Run security review for payload privacy, support-bundle redaction,
  checksum validation, replay authorization, RBAC, and audit evidence.
- [ ] Confirm support bundles include `api/accounting-ingest-spool.json` and no
  raw accounting payload JSON.
- [ ] Capture customer acceptance evidence for operational runbooks, alerting,
  replay drills, and incident response.

## Release Sign-Off Evidence

- [ ] Production Linux FreeRADIUS configuration and version recorded.
- [ ] Device/product/firmware matrix recorded.
- [ ] Packet captures archived with redaction notes.
- [ ] HA drill logs and runtime status snapshots archived.
- [ ] Performance and soak reports archived.
- [ ] Security review outcome archived.
- [ ] Customer or lab acceptance record archived.
