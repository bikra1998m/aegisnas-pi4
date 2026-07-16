# NAS-0017 Release Certification Checklist

Feature: MAC Authentication Bypass workflow

Software implementation status: 100% complete

Ready for external validation: yes

## External Certification / Deployment

- [ ] FreeRADIUS interoperability on supported Linux distributions using generated `files/authorize` MAB entries.
- [ ] Cisco wired MAB smoke test with approved, denied, unknown, and quarantined MACs.
- [ ] Aruba/HPE wired or WLAN MAB smoke test with role and VLAN replies.
- [ ] Juniper/Extreme/Ruckus/HP access-device smoke tests for MAC username formats.
- [ ] MikroTik/UniFi/Fortinet/Cambium compatibility-pack reply validation where MAB is enabled.
- [ ] Packet capture proof for Access-Request, Access-Accept, Access-Reject, VLAN, ACL, and bandwidth replies.
- [ ] Unknown endpoint `deny`, `guest`, `quarantine`, and controlled `fail_open` drills.
- [ ] HA failover validation with endpoint inventory and audit events replicated.
- [ ] Upgrade and rollback validation from the previous production version.
- [ ] Scale benchmark with representative endpoint count and audit retention.
- [ ] Long-duration soak test with periodic reauthentication and profile changes.
- [ ] Security review for MAC spoofing risk, fail-open procedures, audit privacy, and RBAC.
- [ ] Customer acceptance test for the target AP, switch, controller, and firmware set.

## Evidence To Attach

- Generated FreeRADIUS config bundle hash.
- RADIUS packet captures with redacted secrets.
- Admin API `/api/v1/system/mab` response.
- Production readiness report.
- Support bundle containing `api/mab.json`.
- Device/controller model and firmware matrix.
- Failure and rollback drill notes.
