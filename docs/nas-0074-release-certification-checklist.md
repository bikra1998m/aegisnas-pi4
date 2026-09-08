# NAS-0074 Release Certification Checklist

NAS-0074 software implementation is complete when code, API, UI,
configuration, documentation, automation, and automated tests pass. The items
below require external systems, production deployment, physical hardware, or
long-running validation and are tracked separately from engineering completion.

## External Certification

- Obtain local-radio evidence from a supported Linux appliance with hostapd and
  nl80211.
- Validate `dynamic_vlan=1` fallback behavior with a WPA2/WPA3 Enterprise SSID.
- Validate `dynamic_vlan=2` fail-closed behavior when RADIUS returns no VLAN.
- Confirm hostapd consumes `/etc/hostapd/aegisnas-vlans.conf` with generated
  bridge and wireless VLAN interface names.
- Capture RADIUS Access-Accept packets containing `Tunnel-Type`,
  `Tunnel-Medium-Type`, and `Tunnel-Private-Group-Id`.
- Capture negative tests for unsupported VLAN IDs, missing VLAN file entries,
  unsafe bridge names, and missing lifecycle enablement.
- Run FreeRADIUS interoperability on the production Linux target.
- Run vendor AP or controller smoke tests for Cisco, Aruba, Ruckus, Extreme,
  Meraki, UniFi, Cambium, TP-Link, D-Link, Fortinet, Huawei, and MikroTik
  where hostapd-local behavior maps to equivalent RADIUS VLAN semantics.
- Validate CoA-driven VLAN change behavior on representative enterprise APs.
- Validate HA failover and standby activation with active VLAN lifecycle
  snapshots.
- Run performance benchmarks for expected dynamic VLAN SSID/client scale.
- Run long-duration soak testing with repeated preview, apply, rollback, and
  hostapd restart cycles.
- Complete security review for command execution, managed file permissions,
  snapshot evidence, and support-bundle redaction.
- Complete production deployment acceptance and customer sign-off.

## Evidence Required

- Support bundle containing `api/hostapd-vlan-lifecycle.json`.
- Support bundle containing `api/hostapd-vlan-lifecycle-history.json`.
- Packet captures for accepted, rejected, fallback, and fail-closed sessions.
- Hostapd logs for fallback and fail-closed sessions.
- Linux `ip link` state before apply, after apply, after rollback, and after HA
  activation.
- FreeRADIUS debug output for VLAN-bearing Access-Accept replies.
- Firmware/product matrix for tested radios, APs, and controllers.
- Performance and soak-test summaries.

## Release Sign-Off

Release sign-off requires no unresolved Critical defects, complete evidence for
the advertised hardware and vendor scope, rollback proof, HA proof where HA is
advertised, and a successful operator runbook rehearsal.
