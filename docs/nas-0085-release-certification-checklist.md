# NAS-0085 Release Certification Checklist

NAS-0085 software engineering is complete when code, tests, APIs, UI,
configuration, documentation, CI, and evidence persistence are merged. The
items below require external systems, production deployment, customer
environments, real hardware, or long-duration validation, so they do not block
closing engineering implementation.

## External Validation

- [ ] Obtain customer-approved prepaid, postpaid, top-up, rating, quota reset,
  suspension, and grace-period scope.
- [ ] Validate payment gateway settlement, reversal, idempotency, and refund
  handling against the selected provider.
- [ ] Validate BSS/OSS wallet and balance sync against the selected production
  system.
- [ ] Validate FreeRADIUS interoperability on the target production Linux
  release.
- [ ] Capture Access-Request, Access-Accept, Accounting Start, Interim, Stop,
  CoA, and Disconnect packets for each certified vendor/device/firmware tuple.
- [ ] Prove BRAS/BNG behavior for quota warning, hard limit, throttling,
  suspension, top-up recovery, and disconnect recovery.
- [ ] Validate HA replication and failover for quota wallet, top-up, rating,
  reset, and event-ledger tables.
- [ ] Complete performance benchmarks for expected wallet count, session
  count, interim-update rate, rating throughput, and report latency.
- [ ] Complete long-duration soak testing across at least one full quota reset
  period.
- [ ] Complete security review for payment references, top-up idempotency,
  tenant isolation, RBAC, audit logs, and export data.
- [ ] Complete production deployment runbook proof and rollback drill.
- [ ] Complete customer acceptance testing and sign-off.
