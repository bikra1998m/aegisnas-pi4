# NAS-0001 Release Certification Checklist

Feature: `NAS-0001` - Production IANA PEN and lab migration

Engineering status: complete

Purpose: track evidence that depends on external organizations, deployment environments, physical hardware, or sustained certification infrastructure. These items gate a certified production release; they do not reopen NAS-0001 engineering work.

## Identity assignment

- [ ] Obtain an IANA Private Enterprise Number for the product-owning legal organization.
- [ ] Confirm the PEN and exact organization name in the current IANA registry.
- [ ] Archive the dated registry evidence and approval record under release controls.
- [ ] Verify that no lab, documentation, or unrelated organization PEN is used.

## Linux and FreeRADIUS interoperability

- [ ] Exercise preview, apply, and rollback on every supported Ubuntu release.
- [ ] Run `freeradius -XC` against every supported FreeRADIUS release.
- [ ] Verify `freeradius` and `aegis-radius` restart and health behavior.
- [ ] Capture Access, Accounting, CoA, and Disconnect packets using the assigned PEN.
- [ ] Confirm current-PEN precedence and expiry of the bounded legacy-PEN window.

## Vendor hardware interoperability

- [ ] Test every AegisNAS peer and firmware version that consumes product VSAs.
- [ ] Verify unknown-attribute handling and malformed-VSA rejection on real peers.
- [ ] Record packet captures, device configuration, firmware, expected results, and defects.

## HA and recovery

- [ ] Validate active/standby apply with replicated config and database evidence.
- [ ] Inject interruption during apply and prove deterministic recovery.
- [ ] Validate rollback, backup restore, rolling upgrade, and supported downgrade paths.
- [ ] Confirm standby nodes never perform active-node runtime apply operations.

## Performance and endurance

- [ ] Benchmark preview/status history at supported database and session limits.
- [ ] Run long-duration soak testing across migration, accounting, and legacy decode paths.
- [ ] Confirm documented latency, memory, storage, and recovery objectives.

## Security and governance

- [ ] Complete an independent security review of registry fetch, RBAC, confirmation tokens, audit records, and atomic config writes.
- [ ] Complete penetration testing of the migration API and admin UI.
- [ ] Review software bill of materials, dependency findings, and release provenance.
- [ ] Confirm operator dual-control and evidence-retention requirements where applicable.

## Production acceptance

- [ ] Complete customer-environment acceptance testing.
- [ ] Obtain required compliance or certification approvals.
- [ ] Approve production deployment and rollback plans.
- [ ] Attach all evidence to the release record and obtain release sign-off.

## Release gate

A release may claim a production-certified AegisNAS vendor identity only when every applicable item above is complete and the runtime status is `production_verified`. Lab mode remains available while certification is pending.
