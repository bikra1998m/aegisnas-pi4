# NAS-0090 Release Certification Checklist

NAS-0090 software implementation is complete when automated development tests
pass. The following items are external certification, deployment, or
environment-specific validation and do not block engineering completion.

## External Certification / Deployment

- Obtain target BNG, BRAS, router, multicast controller, and access-node
  vendor firmware matrix and exact model scope.
- Validate compiled service activation evidence against FreeRADIUS on
  production Linux.
- Capture Access-Accept, Accounting Start, Interim, Stop, CoA, and Disconnect
  packets carrying route, service, multicast, and accounting evidence.
- Verify `Framed-Route` and `Framed-IPv6-Route` behavior for publish,
  convergence, ownership correlation, withdrawal, duplicate ownership, and
  rollback.
- Verify BGP, OSPF, OSPFv3, IS-IS, or static route adapters used in the target
  deployment with route dampening and failure behavior.
- Verify Cisco, Juniper/ERX, Huawei/H3C, Nokia/Alcatel, ZTE, and any
  customer-required vendor VSAs against the exact supported product and
  firmware versions.
- Verify multicast entitlement with IGMP and MLD joins, leaves, source filters,
  VLAN/VRF scope, and denied group behavior.
- Exercise transactional failure paths for missing subscriber state, inactive
  product, address lease conflict, QoS mismatch, DHCP security failure, route
  adapter outage, multicast profile mismatch, accounting outage, and CoA
  failure.
- Exercise rollback and recovery after partial service activation, route
  adapter failure, multicast entitlement failure, and BNG reboot.
- Run HA failover while service activation transaction rows and event history
  are active.
- Run scale and performance benchmarking at published subscriber, route,
  multicast-group, transaction, and accounting update targets.
- Run long-duration soak with subscriber churn, route churn, multicast joins
  and leaves, accounting replay, route adapter restart, and BNG failover.
- Complete security review for operator RBAC, support bundle redaction, tenant
  isolation, route ownership, multicast entitlement, rollback safety, and CoA
  abuse resistance.
- Complete production deployment runbook and rollback drill.
- Record customer or release-lab acceptance evidence.

## Evidence To Attach

- FreeRADIUS configuration validation output
- packet captures for Access-Accept, Accounting, CoA, Disconnect, route, and
  multicast transitions
- BNG/router CLI/API exports showing route publish, route withdrawal, service
  activation, multicast state, and rollback state
- route adapter logs and routing table snapshots
- multicast forwarding table and IGMP/MLD snooping evidence
- support bundle with NAS-0090 API captures
- production readiness report showing `broadband_service_activation`
- HA failover logs
- performance and soak reports
- security review notes
- signed operator acceptance record
