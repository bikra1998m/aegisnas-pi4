# NAS-0036 Release Certification Checklist

NAS-0036 software engineering is complete when code, automated tests,
configuration, API, UI, CI, and documentation are complete. The items below are
external release evidence and do not block the next roadmap feature.

## External Certification / Deployment

- [ ] FreeRADIUS interoperability on production Linux with duplicate
  `Accounting-Request` retries.
- [ ] Packet-capture proof for reordered `Start`, `Interim-Update`, and `Stop`
  delivery.
- [ ] Vendor AP/controller smoke tests for Cisco, Aruba, Ruckus, Fortinet,
  Juniper/Mist, MikroTik, UniFi, and standards-only clients.
- [ ] HA failover drill showing event replay does not duplicate sessions.
- [ ] Performance benchmark for sustained accounting ingest and replay at the
  selected deployment profile.
- [ ] Long-duration soak test with packet loss, retry, and delayed Stop records.
- [ ] Security audit for event payload redaction and support-bundle contents.
- [ ] Customer acceptance test covering replay and reconciliation evidence.

## Evidence To Capture

- `/api/v1/system/accounting-ordering`
- `/api/v1/system/accounting-ordering/replay`
- `/api/v1/system/sql-accounting`
- `/api/v1/system/production-readiness`
- support bundle entry `api/accounting-ordering.json`
- packet captures for duplicate and reordered accounting traffic
- database snapshots of `radius_accounting_events`, `radacct`, and `sessions`

## Software Completion Statement

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes
