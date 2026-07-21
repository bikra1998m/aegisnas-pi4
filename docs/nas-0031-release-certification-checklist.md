# NAS-0031 Release Certification Checklist

## Software Implementation

- [x] Replay-safe policy evaluation snapshots implemented.
- [x] Candidate-vs-active policy analysis engine implemented.
- [x] Decision delta, blast-radius, conflict, shadowed-rule, and ineffective-rule reporting implemented.
- [x] Risk classification and activation recommendation implemented.
- [x] Persisted analysis records and bounded retention implemented.
- [x] Analysis list and candidate analysis APIs implemented.
- [x] RBAC, OpenAPI, system status, production readiness, and support-bundle evidence implemented.
- [x] Policies page and Dashboard analysis summaries implemented.
- [x] Unit, integration, migration, API, readiness, support-bundle, and frontend build coverage added.
- [x] Operator, API, configuration, and roadmap documentation updated.

Software Implementation: 100% Complete

Engineering Implementation: 100% Complete

Ready for External Validation: Yes

## External Certification / Deployment

- [ ] FreeRADIUS lab replay verifies candidate-vs-active results against packet-capture decisions.
- [ ] Vendor AP/switch/controller smoke tests validate representative allow, deny, quarantine, VLAN, ACL, and bandwidth changes.
- [ ] HA pair validates analysis persistence and replay behavior across active/standby failover.
- [ ] Performance benchmark covers large retained histories and large nested policy sets on Lite, Branch, and Enterprise profiles.
- [ ] Long-duration soak test confirms retention pruning and analysis stability.
- [ ] Security review verifies replay snapshot redaction and sensitive attribute filtering.
- [ ] Customer acceptance validates blast-radius wording, risk thresholds, and approval workflow.

External validation is required for production release claims but does not block
completion of NAS-0031 engineering work.
