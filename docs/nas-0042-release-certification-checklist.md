# NAS-0042 Release Certification Checklist

NAS-0042 software engineering is complete when automated tests and builds pass.
The items below require real hardware, production Linux services, third-party
environments, or long-running validation and do not keep the engineering
roadmap item open.

## External Validation

- Capture CoA-Request, CoA-ACK, CoA-NAK, Disconnect-Request,
  Disconnect-ACK, and Disconnect-NAK packets against FreeRADIUS on production
  Linux.
- Verify Message-Authenticator acceptance with packet captures and negative
  tamper cases.
- Validate Cisco, Aruba, Juniper, Ruckus, Fortinet, MikroTik, Huawei, UniFi,
  Mist, Extreme, and Cambium devices or controllers for the vendor-neutral
  attributes supported by NAS-0042.
- Record exact vendor, product, firmware, and transport scope for each result.
- Run controlled timeout, no-route, bad-secret, NAK Error-Cause, and unexpected
  response drills.
- Validate HA failover behavior for immediate outbound sends; durable queue and
  ownership behavior belongs to NAS-0043 through NAS-0047.
- Run performance benchmarks for preview and immediate send API latency.
- Run long-duration soak testing with bounded history retention.
- Complete security review for RBAC, audit logs, secret handling, selector
  redaction, and support bundle output.
- Complete customer acceptance testing in at least one lab and one production
  staging environment.

## Release Evidence

- FreeRADIUS interoperability logs.
- Packet captures with secrets excluded or securely escrowed.
- Vendor matrix with ACK/NAK/error outcomes.
- Support bundle from a completed change window.
- Production readiness report showing `radius_outbound_dac_client`.
- Rollback or mitigation procedure for misapplied CoA/Disconnect operations.

## Sign-Off

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes
