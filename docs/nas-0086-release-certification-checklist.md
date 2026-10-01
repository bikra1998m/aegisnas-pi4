# NAS-0086 Release Certification Checklist

NAS-0086 software implementation is complete when code, database migrations, API, UI, tests, automation, and documentation pass. The items below require external organizations, production deployment, third-party systems, physical hardware, or customer environments and do not block engineering completion.

## External Certification / Deployment

- [ ] Confirm live FreeRADIUS interoperability on the target Linux distribution with IPv4, IPv6, and delegated-prefix reply attributes.
- [ ] Validate Cisco broadband address pool and CoA conflict recovery behavior.
- [ ] Validate Juniper ERX/E-Series address/prefix pool behavior.
- [ ] Validate Huawei BRAS/BNG IPv4, IPv6, and delegated-prefix pool behavior.
- [ ] Validate Nokia/Alcatel-Lucent SR OS delegated-prefix behavior.
- [ ] Validate MikroTik pool and address-list interoperability.
- [ ] Capture Access-Accept, Accounting-Start, Accounting-Interim, Accounting-Stop, CoA, and Disconnect packets.
- [ ] Drill duplicate IPv4 address conflict recovery.
- [ ] Drill duplicate IPv6 delegated-prefix conflict recovery.
- [ ] Drill accounting-stop release and reconnect sticky ownership.
- [ ] Drill reservation override behavior with a real CPE.
- [ ] Drill active/standby HA replay of lease ownership rows.
- [ ] Run scale and performance benchmarks for expected subscriber count.
- [ ] Run long-duration lease soak with interim accounting.
- [ ] Complete security review for lease ownership, tenant separation, logs, and support bundles.
- [ ] Complete production deployment acceptance with rollback proof.

## Evidence To Attach

- FreeRADIUS debug logs and packet captures
- Vendor controller or BNG screenshots/log exports
- AegisNAS `/api/v1/system/broadband-address-leases` output
- AegisNAS `/api/v1/system/broadband-address-leases/history` output
- Support bundle containing `api/broadband-address-leases.json`
- HA failover logs and database replication proof
- Performance benchmark report
- Soak test report
- Customer acceptance notes
