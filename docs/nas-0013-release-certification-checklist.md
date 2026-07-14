# NAS-0013 Release Certification Checklist

Feature: Dynamic NAS clients and capability discovery

Software implementation status: 100% complete

Engineering implementation status: 100% complete

Ready for external validation: Yes

This checklist tracks evidence that depends on real hardware, third-party services, customer environments, long-duration labs, or production deployment. These activities do not block closing NAS-0013 engineering work.

## External Certification / Deployment

- [ ] IANA/vendor identity evidence is current for any product-branded dictionaries used in enrollment workflows.
- [ ] FreeRADIUS interoperability is validated on the supported production Linux distributions.
- [ ] UDP RADIUS client approval is validated with at least one AP or switch per certified vendor pack.
- [ ] RadSec client approval is validated with certificate CN matching, issuer constraints, and RADIUS/1.1 policy where applicable.
- [ ] Packet discovery is validated with unknown sources and confirmed to remain fail-closed.
- [ ] Source spoofing and wrong-token enrollment attempts are captured in evidence.
- [ ] Capability-template rejection is tested with missing VLAN, role, accounting, and CoA capabilities.
- [ ] Revocation disables the generated RADIUS client and blocks subsequent packets.
- [ ] HA validation confirms enrollment, approval, revocation, and heartbeat state survive node failover.
- [ ] PostgreSQL validation confirms schema v20 migration and repair on an external database.
- [ ] Performance benchmarking covers high enrollment churn, heartbeat volume, and large static plus dynamic client inventories.
- [ ] Long-duration soak confirms event retention, last-seen updates, and approval queue stability.
- [ ] Security audit reviews token handling, secret-reference handling, RBAC, source-IP binding, and audit events.
- [ ] Customer acceptance testing confirms the operator workflow for branch AP/switch onboarding.

## Evidence To Attach

- production config excerpt with `radius.dynamic_clients` policy
- OpenAPI export showing NAS enrollment and lifecycle endpoints
- `/api/v1/system/status` response with `radius.dynamic_nas_clients`
- `/api/v1/system/production-readiness` response showing `dynamic_nas_clients`
- packet captures for unknown-source reject, approved client accept path, and revoked client reject path
- FreeRADIUS generated client configuration before and after approval
- HA failover logs and database records
- performance and soak reports
- signed security review notes
