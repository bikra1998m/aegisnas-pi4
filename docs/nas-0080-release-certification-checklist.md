# NAS-0080 Release Certification Checklist

NAS-0080 engineering implementation is complete when code, schema, APIs, UI, tests, CI hooks, and documentation pass. The items below are external certification or deployment activities and do not block roadmap progress.

## External Certification / Deployment

- Obtain real AP/controller hardware for each claimed vendor, model, and firmware.
- Validate rogue classification against benign neighbor APs, managed APs, spoofed BSSIDs, evil twin APs, honeypots, and noisy RF environments.
- Validate containment behavior only where legally authorized and only with explicit operator approval.
- Capture spectrum samples for each supported radio chipset, band, channel width, DFS condition, and interference type.
- Validate location accuracy, zone assignment, privacy mode, hashed identifiers, retention, and coordinate export controls with a privacy review.
- Validate multicast behavior for IGMP, MLD, mDNS, SSDP, broadcast filtering, multicast-to-unicast conversion, IPv6 multicast, roaming clients, and high client density.
- Prove controller API mutation and rollback behavior for Cisco, Aruba, Ruckus, Extreme, Meraki, UniFi, Cambium, Juniper Mist, Fortinet, MikroTik, OpenWiFi, and hostapd scopes that will be claimed.
- Run FreeRADIUS interoperability tests for RADIUS, Accounting, and CoA quarantine workflows on production Linux.
- Run HA failover tests while preview/apply/history operations and runtime status updates are active.
- Run scale, performance, and long-duration soak tests with realistic AP, sensor, client, and multicast loads.
- Complete security audit for containment guardrails, privacy controls, support bundle redaction, and API authorization.
- Complete production deployment, customer acceptance, and compliance evidence for any regulated environment.

## Evidence To Attach

- Hardware inventory with firmware versions.
- Packet captures and controller API traces.
- Before/after multicast airtime measurements.
- Spectrum analyzer captures.
- Location accuracy reports and privacy review notes.
- CoA/quarantine transcripts.
- HA failover logs.
- Performance and soak reports.
- Signed customer or lab acceptance record.
