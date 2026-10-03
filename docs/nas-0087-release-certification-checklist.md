# NAS-0087 Release Certification Checklist

NAS-0087 software implementation is complete when automated development tests
pass. The following items are external certification, deployment, or
environment-specific validation and do not block engineering completion.

## External Certification / Deployment

- Obtain target BNG vendor firmware matrix and exact model scope.
- Validate compiled QoS attributes against FreeRADIUS on production Linux.
- Capture Access-Accept packets for MikroTik, Huawei, Nokia/Alcatel-Lucent,
  Cisco BNG, Juniper ERX/E-Series, Starent, WiMAX, and any customer-required
  vendor pack.
- Prove service-flow activation on real BNG hardware or a certified lab emulator.
- Verify parent-child hierarchy behavior, scheduler mode, priority, DSCP marking,
  aggregate limits, and oversubscription policy.
- Exercise quota-triggered and product-change CoA updates.
- Confirm accounting Start, Interim-Update, and Stop correlation for active flow
  ownership.
- Run HA failover while service-flow rows and event history are active.
- Run scale and performance benchmarking at the published subscriber and flow
  targets.
- Run long-duration QoS soak with reconnect, quota, and aggregate changes.
- Run packet capture validation for unsupported-attribute and compiler-diagnostic
  paths.
- Complete security review for operator RBAC, audit evidence, and support bundle
  redaction.
- Complete production deployment runbook and rollback drill.
- Record customer or release-lab acceptance evidence.

## Evidence To Attach

- FreeRADIUS configuration validation output
- packet captures for Access-Accept and CoA
- BNG CLI/API screenshots or exports showing active queues/service flows
- support bundle with NAS-0087 API captures
- production readiness report showing `broadband_qos_service_flows`
- HA failover logs
- performance and soak reports
- signed operator acceptance record
