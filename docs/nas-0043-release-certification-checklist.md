# NAS-0043 Release Certification Checklist

NAS-0043 software engineering is complete when automated tests and builds pass.
The items below require real hardware, production Linux services, third-party
environments, or long-running validation and do not keep the engineering roadmap
item open.

## External Validation

- Capture queued CoA-Request and Disconnect-Request replay against FreeRADIUS on
  production Linux, including ACK, NAK with Error-Cause, timeout retry, and
  exhausted dead-letter cases.
- Validate duplicate suppression by replaying the same operator workflow with
  the same idempotency key across service restarts.
- Validate Cisco, Aruba, Juniper, Ruckus, Fortinet, MikroTik, Huawei, UniFi,
  Mist, Extreme, and Cambium behavior for retry after transient packet loss.
- Record exact vendor, product, firmware, transport, retry, timeout, and
  Error-Cause behavior for each result.
- Drill queue expiry, poison review, manual cancel, and manual retry during a
  controlled maintenance window.
- Validate HA failover behavior for queued records, owner locks, and replay
  after node restart; distributed session ownership is finalized in NAS-0046 and
  cluster handoff in NAS-0047.
- Run performance benchmarks for enqueue, replay batch, history, and readiness
  APIs at Lite, Branch, and Enterprise queue sizes.
- Run long-duration soak testing with packet loss, bad shared secrets, no-route
  targets, service restarts, and bounded retention pruning.
- Complete security review for RBAC, audit logs, idempotency keys, payload
  persistence, selector redaction, support bundles, and secret resolution.
- Complete customer acceptance testing in at least one lab and one production
  staging environment.

## Release Evidence

- FreeRADIUS interoperability logs.
- Packet captures with secrets excluded or securely escrowed.
- Queue state snapshots before and after ACK, NAK, retry, poison, cancel, retry,
  expiry, and retention pruning.
- Vendor matrix with replay and Error-Cause outcomes.
- Support bundle from a completed queued change window.
- Production readiness report showing `radius_outbound_dac_client`.
- Rollback or mitigation procedure for misapplied queued CoA/Disconnect
  operations.

## Sign-Off

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes
