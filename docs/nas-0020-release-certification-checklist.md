# NAS-0020 Release Certification Checklist

Software engineering for NAS-0020 can be complete before these external activities finish.

## External Certification / Deployment

- [ ] Confirm production `AEGIS_MFA_SEALING_KEY` generation, custody, backup, and rotation procedure.
- [ ] Run FreeRADIUS interoperability tests on production Linux with `Access-Challenge`, `State`, and `Reply-Message` captures.
- [ ] Validate Cisco ASA/AnyConnect RADIUS challenge flow.
- [ ] Validate Fortinet SSL VPN or firewall RADIUS challenge flow.
- [ ] Validate Palo Alto GlobalProtect RADIUS challenge flow.
- [ ] Validate Microsoft NPS or MFA extension challenge flow.
- [ ] Validate Aruba/HPE wireless or VPN challenge behavior where available.
- [ ] Run HA failover while challenges are pending and confirm database-backed state survives.
- [ ] Run performance benchmark with configured `mfa.radius_challenge.max_pending`.
- [ ] Run long-duration soak with TOTP enroll/verify/rotate/audit traffic.
- [ ] Run security review for MFA enrollment handling, recovery-code delivery, replay, brute-force limits, and support-bundle redaction.
- [ ] Capture customer acceptance evidence for the exact enabled products and firmware versions.

## Software Implementation Status

| Area | Status |
|---|---|
| Configuration and validation | Complete |
| Database migration and repair | Complete |
| Encrypted TOTP enrollment | Complete |
| Recovery codes | Complete |
| Portal step-up flow | Complete |
| RADIUS Access-Challenge state handling | Complete |
| Admin API and OpenAPI | Complete |
| UI visibility and settings | Complete |
| Readiness and support bundle evidence | Complete |
| Automated software tests | Complete |
