# NAS-0030 Release Certification Checklist

## Software Implementation

- [x] Nested policy-set schema and compiler implemented.
- [x] Immutable version storage implemented.
- [x] Maker-checker approval lifecycle implemented.
- [x] Submit, approve, reject, activate, rollback, compare, and simulate APIs implemented.
- [x] Active version evaluation integrated with the typed policy engine.
- [x] Activation mirrors flattened policy rules into legacy `policy_rules` for backward compatibility.
- [x] Database migration v35 implemented.
- [x] Admin UI exposes active version, pending approvals, create, submit, approve, activate, and rollback controls.
- [x] Dashboard, system status, support bundle, OpenAPI, RBAC, and production readiness evidence implemented.
- [x] Unit, integration, API, migration, readiness, support bundle, and frontend build coverage added.
- [x] Operator, API, and roadmap documentation updated.

Software Implementation: 100% Complete

Engineering Implementation: 100% Complete

Ready for External Validation: Yes

## External Certification / Deployment

- [ ] FreeRADIUS lab run verifies activated version output against generated `users` and policy behavior.
- [ ] Vendor AP/switch/controller smoke tests verify representative VLAN, ACL, quarantine, and deny decisions.
- [ ] HA pair validates active-version replication and rollback on active/standby failover.
- [ ] Performance benchmark covers large nested policy trees and concurrent simulations.
- [ ] Long-duration soak test confirms activation, rollback, audit, and retention behavior.
- [ ] Security review verifies maker-checker, RBAC, tenant scoping assumptions, and audit integrity.
- [ ] Customer acceptance validates the operational workflow and approval wording.

External validation is required for production release claims but does not block
completion of NAS-0030 engineering work.
