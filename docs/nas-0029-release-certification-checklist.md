# NAS-0029 Release Certification Checklist

Feature: Typed policy expression engine

## Software Implementation

- [x] Typed expression AST with `all`, `any`, `not`, and leaf nodes
- [x] Field and operator catalog
- [x] Legacy `match_conditions` compiler for migration
- [x] Deterministic evaluation, conflict detection, hashes, and explain traces
- [x] Staged policy apply validation
- [x] Schema v34 `policy_engine_evaluations`
- [x] Redacted evaluation history and retention
- [x] Admin API status, validate, and evaluate endpoints
- [x] Standalone policy service detailed evaluation and catalog endpoints
- [x] RBAC, OpenAPI, system status, production readiness, support bundle
- [x] Policies page typed/legacy/valid posture
- [x] Dashboard policy-engine posture
- [x] Unit, DB, config, API, RBAC, OpenAPI, readiness, support-bundle, build, and frontend coverage
- [x] Operator documentation

Software Implementation: 100% Complete

Engineering Implementation: 100% Complete

Ready for External Validation: Yes

## External Certification / Deployment

- [ ] FreeRADIUS production Linux interoperability using generated policy decisions
- [ ] Packet-capture evidence for Access-Accept, Access-Reject, VLAN, ACL, timeout, quarantine, and vendor reply combinations
- [ ] Cisco, Aruba, Juniper, Fortinet, Ruckus, MikroTik, Ubiquiti, and OpenWiFi smoke tests
- [ ] HA active/standby evaluation continuity and support-bundle evidence
- [ ] Performance benchmark with large rule sets and high request concurrency
- [ ] Long-duration soak testing with policy history retention enabled
- [ ] Security review of regex bounds, request redaction, RBAC, and tenant facts
- [ ] Customer acceptance testing for policy migration from legacy JSON to typed expressions
