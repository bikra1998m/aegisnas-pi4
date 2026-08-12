# NAS-0051 Release Certification Checklist

## Software Implementation

- [x] Hierarchical QoS scheduler planner implemented.
- [x] Existing `bandwidth_profiles` remain backward compatible.
- [x] `qos_scheduler_profiles` overrides implemented.
- [x] Runtime `tc`/IFB command plan generation implemented.
- [x] Aggregate profile classes implemented.
- [x] Per-session leaf classes implemented.
- [x] `fq_codel` leaf queueing implemented.
- [x] Priority, burst, committed burst, quantum, aggregate cap, and DSCP
      metadata validation implemented.
- [x] Preview/apply/sync/rollback evidence implemented.
- [x] Snapshot rollback implemented.
- [x] Admin API, RBAC, OpenAPI, system status, production readiness, support
      bundle, and Dashboard visibility implemented.
- [x] Unit, migration, DB, API, RBAC, readiness, support-bundle, and UI build
      coverage implemented.
- [x] Operator documentation implemented.

Software Implementation: 100% Complete

Engineering Implementation: 100% Complete

Ready for External Validation: Yes

## External Certification / Deployment

- [ ] Validate generated `tc`/IFB commands on Ubuntu and Raspberry Pi OS.
- [ ] Capture packets proving download and upload class selection.
- [ ] Measure throughput and latency under per-session and aggregate caps.
- [ ] Validate `fq_codel` behavior under congestion.
- [ ] Run FreeRADIUS Linux interoperability with live Access-Accept bandwidth
      profile assignment.
- [ ] Validate CoA-triggered bandwidth profile changes with live sessions.
- [ ] Run vendor/controller smoke tests for Cisco, Huawei, Juniper, MikroTik,
      and WiMAX/BNG-style QoS expectations.
- [ ] Run HA failover and rollback drills.
- [ ] Run performance, scale, and long-duration soak tests.
- [ ] Complete security review for command execution, RBAC, and audit evidence.
- [ ] Complete production deployment and customer acceptance evidence.
