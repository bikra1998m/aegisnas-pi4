# NAS-0091 Release Certification Checklist

NAS-0091 software implementation is complete when automated development tests
pass. The following items are external certification, deployment, legal, or
environment-specific validation and do not block engineering completion.

## External Certification / Deployment

- Obtain written product, legal, privacy, and compliance ownership for the
  target lawful-governance workflow.
- Obtain target BNG, BRAS, controller, lawful-intercept adapter, and access
  vendor firmware matrix and exact model scope.
- Validate compiled lawful-governance and self-service evidence against
  FreeRADIUS on production Linux.
- Capture Access-Accept, Accounting Start, Interim, Stop, CoA, and Disconnect
  packets carrying lawful case, self-service, privacy, and accounting
  correlation evidence.
- Verify Cisco, Juniper/ERX, Huawei/H3C, Nokia/Alcatel-Lucent, Ericsson, and
  any customer-required vendor VSAs against exact supported product and
  firmware versions.
- Verify lawful-intercept adapter handoff, export redaction, audit custody, and
  retention behavior in the target legal environment.
- Exercise approval failure paths for missing MFA, missing WebAuthn, missing
  dual control, expired case, unauthorized role, disabled privacy policy,
  accounting outage, and dynamic authorization failure.
- Exercise subscriber self-service paths for balance view, plan change, top-up,
  usage export, privacy request, support ticket, service cancellation, denied
  product, denied tenant, rate limit, and pending-request limit.
- Run HA failover while governance case rows, self-service rows, runtime
  status, and event history are active.
- Run scale and performance benchmarking at published case, self-service
  request, accounting update, and support-bundle evidence targets.
- Run long-duration soak with subscriber churn, repeated self-service actions,
  accounting replay, admin approval rotation, database restart, and HA failover.
- Complete security review for operator RBAC, MFA/WebAuthn enforcement,
  support bundle redaction, tenant isolation, privacy export, CoA abuse
  resistance, and legal-audit tamper resistance.
- Complete production deployment runbook and rollback drill.
- Record regulator, customer, or release-lab acceptance evidence.

## Evidence To Attach

- FreeRADIUS configuration validation output
- packet captures for Access-Accept, Accounting, CoA, Disconnect, and governed
  subscriber action transitions
- BNG/router/controller CLI/API exports showing lawful-governance and
  self-service correlation evidence
- lawful-intercept adapter logs and redacted export manifests
- immutable approval, MFA, WebAuthn, and audit evidence
- privacy redaction samples and retention policy proof
- support bundle with NAS-0091 API captures
- production readiness report showing `broadband_governance_self_service`
- HA failover logs
- performance and soak reports
- security review notes
- signed legal/compliance/operator acceptance record
