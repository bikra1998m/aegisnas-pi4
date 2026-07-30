# NAS-0035 Release Certification Checklist

NAS-0035 software implementation is complete when code, tests, docs, API, UI,
and CI are committed. The items below require external systems, real Linux
deployments, real FreeRADIUS packages, vendor devices, or long-running
environments and do not block engineering closure.

## FreeRADIUS Lab

- Install the supported FreeRADIUS release on Ubuntu.
- Generate and apply AegisNAS FreeRADIUS configuration.
- Confirm the SQL module can read and write `radacct`.
- Confirm `radpostauth` writes for accept, reject, and challenge outcomes.
- Capture `radiusd -X` evidence for accounting start, interim, and stop.
- Capture packet traces for RFC 2866 accounting fields.

## Database

- Validate SQLite on lite hardware.
- Validate PostgreSQL on enterprise HA topology.
- Run schema upgrade from the previous release to schema v40.
- Run rollback rehearsal to the previous release.
- Confirm retention pruning does not remove active or pending rows.

## Vendor Hardware

- Test at least one AP or switch using direct AegisNAS RADIUS.
- Test one external FreeRADIUS SQL writer against the product database.
- Test one upstream AAA proxy path with accounting enabled.
- Confirm vendor `Class`, station IDs, NAS identifiers, and stop causes remain
  visible after reconciliation.

## HA And Recovery

- Validate active/standby behavior with PostgreSQL.
- Reconcile pending rows after a controlled primary-node failure.
- Confirm no duplicate session closure after standby promotion.
- Confirm support bundle capture after failover.

## Performance And Soak

- Benchmark reconciliation batches at lite, branch, and enterprise profiles.
- Run 24-hour accounting soak with start, interim, and stop traffic.
- Measure database size and prune behavior at configured retention.
- Confirm production readiness remains passed after soak.

## Security

- Confirm no clear-text password is stored in `radpostauth`.
- Confirm support bundle redaction keeps secrets out of artifacts.
- Review API authorization for read-only and ops roles.
- Run vulnerability and dependency scans.

## Customer Acceptance

- Document exact FreeRADIUS release, database backend, OS, kernel, and vendor
  firmware tested.
- Attach support bundle evidence.
- Attach packet captures and reconciliation logs.
- Record known limitations assigned to NAS-0036 through NAS-0041.
