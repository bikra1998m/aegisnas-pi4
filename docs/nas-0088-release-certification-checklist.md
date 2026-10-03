# NAS-0088 Release Certification Checklist

NAS-0088 software implementation is complete when automated development tests
pass. The following items are external certification, deployment, or
environment-specific validation and do not block engineering completion.

## External Certification / Deployment

- Obtain target LAC/LNS vendor firmware matrix and exact model scope.
- Validate compiled L2TP attributes against FreeRADIUS on production Linux.
- Capture Access-Accept packets for Cisco, Juniper ERX/E-Series,
  Nokia/Alcatel-Lucent SR OS, Huawei/H3C, ADSL-Forum-style deployments, and any
  customer-required wholesale vendor pack.
- Prove L2TP tunnel establishment against real LNS hardware or a certified lab
  emulator.
- Verify realm matching, customer realm stripping, tenant separation, proxy
  route selection, and accounting route delegation.
- Exercise primary-to-backup tunnel failover with accounting replay.
- Exercise CoA or Disconnect recovery after tunnel failure and route withdrawal.
- Confirm accounting Start, Interim-Update, and Stop delegation for active
  wholesale sessions.
- Run HA failover while realm bindings and event history are active.
- Run scale and performance benchmarking at the published subscriber and tunnel
  targets.
- Run long-duration L2TP soak with reconnect, interim accounting, and failover
  events.
- Run packet capture validation for unsupported-attribute and failover-blocker
  paths.
- Complete security review for operator RBAC, secret references, audit evidence,
  support bundle redaction, and partner route isolation.
- Complete production deployment runbook and rollback drill.
- Record customer or release-lab acceptance evidence.

## Evidence To Attach

- FreeRADIUS configuration validation output
- packet captures for Access-Accept, Accounting, CoA, and Disconnect
- LAC/LNS CLI/API screenshots or exports showing active tunnels and sessions
- partner route and accounting delegation acceptance proof
- support bundle with NAS-0088 API captures
- production readiness report showing `broadband_l2tp_wholesale`
- HA failover logs
- performance and soak reports
- signed operator acceptance record
