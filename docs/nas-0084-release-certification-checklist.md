# NAS-0084 Release Certification Checklist

Feature: Plans, products, service bundles, and concurrent sessions

## Software Status

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes
- External activities do not block NAS-0084 engineering closure or the next
  roadmap item.

## External Certification And Deployment

- [ ] Obtain customer-approved commercial catalog scope, billing products,
  recurring periods, grace rules, suspension states, and concurrent session
  policy.
- [ ] Validate BSS/OSS and CRM source-of-truth sync for account, plan, bundle,
  subscription, status, and entitlement data.
- [ ] Validate live FreeRADIUS production Linux interoperability with Access-
  Accept, Accounting Start, Interim-Update, Stop, CoA, and Disconnect packet
  captures.
- [ ] Validate BRAS/BNG and NAS hardware interoperability for every claimed
  vendor, product, and firmware version.
- [ ] Validate subscription suspension, reactivation, grace-period handling,
  and concurrent-session enforcement against live access devices.
- [ ] Validate vendor-specific reply behavior for Cisco AVPair, MikroTik
  rate-limit, Huawei/H3C/Nokia/ZTE subscriber hints, and any enabled
  compatibility pack used by the deployment.
- [ ] Validate high availability replication and failover for commercial catalog
  records, applied checkpoints, runtime status, and event history.
- [ ] Run scale benchmarks for account, plan, subscription, session, and event
  counts that match the published deployment profile.
- [ ] Run long-duration soak tests with accounting bursts, duplicate interim
  updates, late stops, reconnects, and over-limit CoA actions.
- [ ] Complete security review for tenant isolation, RBAC, audit history,
  support bundles, redaction, and billing/customer PII handling.
- [ ] Validate backup, restore, migration, rollback, and schema repair on the
  target production database backend.
- [ ] Complete production deployment runbook rehearsal and customer acceptance
  testing.

## Evidence To Attach

- API preview/apply outputs with plan fingerprint.
- Packet captures for RADIUS auth, accounting, CoA, and disconnect flows.
- FreeRADIUS debug logs from the production Linux baseline.
- Vendor device CLI/controller screenshots or exports for accepted attributes.
- BSS/OSS sync logs or signed test evidence.
- HA failover logs and database replication checks.
- Performance and soak reports.
- Security review sign-off.
- Customer acceptance record.
