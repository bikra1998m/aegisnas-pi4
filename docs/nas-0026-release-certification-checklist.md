# NAS-0026 Release Certification Checklist

## Software Implementation

- [x] Config schema and validation for `radius.eap.machine_user`.
- [x] Deterministic machine/user correlation evaluator.
- [x] Fresh-machine, same-client, same-NAS, machine-before-user, transition,
  role-merge, conflict, quarantine, and replay handling.
- [x] Hashed event history in `eap_machine_user_correlations`.
- [x] Current hashed correlation state in `eap_machine_user_session_state`.
- [x] REST API, OpenAPI, RBAC, support-bundle capture, system status, and
  production-readiness integration.
- [x] Access Settings controls and Dashboard runtime visibility.
- [x] Unit, integration, API, migration, readiness, support-bundle, and CI
  target coverage.
- [x] Operator, API, EAP framework, external AAA, roadmap, and backlog
  documentation.

Software Implementation: 100% Complete

Engineering Implementation: 100% Complete

Ready For External Validation: Yes

## External Certification / Deployment

- [ ] Validate with Microsoft Windows machine and user authentication.
- [ ] Validate with Microsoft NPS where applicable.
- [ ] Validate with Cisco ISE machine/user authorization workflows.
- [ ] Validate with Aruba ClearPass machine/user authorization workflows.
- [ ] Validate with HP/Aruba switch and WLAN client sessions.
- [ ] Capture TEAP Identity-Type, Crypto-Binding, Result, `Calling-Station-Id`,
  `NAS-Identifier`, role, VLAN, and Class evidence.
- [ ] Run stale-machine, user-before-machine, same-client mismatch, same-NAS
  mismatch, role conflict, quarantine, and replay negative tests.
- [ ] Run roaming and reauthentication drills with real AP/controller firmware.
- [ ] Run HA failover while correlated sessions are active.
- [ ] Run performance, scale, and long-duration soak tests at supported
  correlation-state limits.
- [ ] Complete security review for identity privacy, hash-only telemetry,
  downgrade resistance, and fail-closed behavior.
- [ ] Retain support bundles with `api/eap-framework-machine-user.json`.
- [ ] Obtain customer acceptance evidence for claimed vendor/product/firmware
  combinations.
