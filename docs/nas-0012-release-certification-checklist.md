# NAS-0012 Release Certification Checklist

Feature: Durable proxy accounting spool

Software implementation is complete. The following items are external validation and release-signoff work.

## External Certification / Deployment

- IANA PEN assignment and production vendor identity active.
- FreeRADIUS interoperability on production Linux with accounting proxy enabled.
- Vendor hardware interoperability for representative AP, switch, controller, and BNG devices.
- Controlled outage drill: upstream accounting server down, records queued, server restored, records replayed.
- Controlled malformed-response drill: unexpected response codes move through retry and poison handling.
- HA validation with shared or replicated database, node failover, stale lock recovery, and no duplicate replay.
- Upgrade validation from the previous release with queued, retrying, sent, poison, and expired rows present.
- Rollback validation preserving readable spool data or documented forward-only behavior.
- Scale benchmark for Lite, Branch, and Enterprise profiles.
- Long-duration soak with interim accounting load and upstream flaps.
- Security audit of payload retention, RBAC, operator replay, database access, and log redaction.
- Customer acceptance testing in a pilot environment.

## Evidence To Attach

- FreeRADIUS debug logs showing proxied `Accounting-Request` and `Accounting-Response`.
- Packet captures for Start, Interim-Update, Stop, retry, duplicate suppression, and replay.
- Database before/after snapshots for queued, retrying, sent, poison, and expired states.
- API outputs from `/api/v1/system/accounting-spool` and production readiness.
- Dashboard screenshots showing queue health and poison warnings.
- HA failover timeline with node ownership and lock expiry evidence.
- Performance report with records/sec, latency, queue depth, CPU, memory, and DB growth.

## Release Gate

Release certification passes when all external evidence is attached, signed, reviewed, and there are zero unresolved Critical defects for NAS-0012.
