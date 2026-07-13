# NAS-0009 Release Certification Checklist

NAS-0009 software implementation is complete when code, tests, API, UI, configuration, documentation, and CI automation are committed. The items below require external systems, production Linux, real NAS/controller hardware, or formal security review and do not block development of NAS-0010.

## External Validation

- Install the generated FreeRADIUS configuration on Ubuntu with FreeRADIUS 3.2.8 or the release-pinned package.
- Run `freeradius -XC` with packet hardening enabled and `require_message_authenticator = auto`.
- Capture and archive Access-Request, Accounting-Request, Status-Server, CoA-Request, and Disconnect-Request samples.
- Verify EAP Access-Request packets without `Message-Authenticator` are rejected.
- Verify valid EAP, Status-Server, CoA, and Disconnect packets with `Message-Authenticator` are accepted.
- Verify malformed length, truncated attribute, excessive Proxy-State, replay, unknown-source, and rate-limit cases are rejected.
- Validate RadSec behavior with mutual TLS peers where available.
- Run HA active/standby failover while replay and rate-limit state is active.
- Run controller/NAS interoperability smoke tests for Cisco, Aruba, UniFi, Ruckus, Fortinet, MikroTik, Mist, and any customer-selected vendors.
- Perform a 24-hour soak test with normal authentication and accounting load.
- Review hardening event retention under packet-flood conditions on low-spec and enterprise profiles.
- Complete security review for denial-of-service resistance and log redaction.

## Evidence To Archive

- FreeRADIUS `-XC` output.
- Packet captures with secrets redacted.
- Admin API `/api/v1/system/radius-hardening` JSON.
- Production readiness JSON.
- HA failover logs.
- Vendor/controller firmware versions.
- Test topology and IP plan.
- Any exceptions approved for `require_message_authenticator=never` or `allow_status_client=true`.
