# NAS-0075 Release Certification Checklist

NAS-0075 software implementation is complete when code, API, UI,
configuration, documentation, automation, and automated tests pass. The items
below require external systems, production deployment, physical hardware, or
long-running validation and are tracked separately from engineering completion.

## External Certification

- Validate 802.11r Fast Transition on a supported Linux appliance with
  hostapd/nl80211 and at least two AP/BSSIDs in one mobility domain.
- Validate WPA2-Enterprise FT-EAP and WPA3-Enterprise FT-EAP behavior with real
  supplicants.
- Validate WPA2/WPA3 Personal FT behavior where advertised.
- Confirm PMF-required behavior and failure handling for incompatible clients.
- Confirm IEEE 802.11k neighbor reports and beacon reports on supported
  clients.
- Confirm IEEE 802.11v BSS transition requests and client steering behavior on
  supported clients.
- Capture successful roam, failed roam, reassociation timeout, key-rotation,
  and neighbor-missing scenarios.
- Validate accounting continuity across roam using `Acct-Session-Id`,
  `Acct-Multi-Session-Id`, `Calling-Station-Id`, `Called-Station-Id`, and
  `Class`.
- Validate CoA and Disconnect behavior during or after roam on representative
  vendor devices.
- Run FreeRADIUS interoperability on the production Linux target.
- Run vendor AP/controller smoke tests for Cisco, Aruba, Ruckus, Extreme,
  Meraki, UniFi, Juniper Mist, Fortinet, OpenWiFi, and hostapd where roaming
  behavior is advertised.
- Validate HA failover and standby activation with roaming lifecycle history
  intact and no secret disclosure.
- Run performance benchmarks for expected AP, SSID, neighbor, and client scale.
- Run long-duration soak testing with repeated preview, apply, key rotation,
  roam, hostapd restart, and HA failover cycles.
- Complete security review for FT key derivation, secret references, file
  permissions, support-bundle redaction, logs, and UI payloads.
- Complete production deployment acceptance and customer sign-off.

## Evidence Required

- Support bundle containing `api/wireless-roaming-lifecycle.json`.
- Support bundle containing `api/wireless-roaming-lifecycle-history.json`.
- Hostapd generated config with `r0kh` and `r1kh` keys redacted in evidence.
- Packet captures for association, reassociation, EAP, accounting continuity,
  CoA, and disconnect flows.
- Hostapd logs for successful and failed FT attempts.
- FreeRADIUS debug output for corresponding Access, Accounting, and CoA flows.
- Product, controller, firmware, client OS, and supplicant compatibility
  matrix.
- HA failover transcript and lifecycle event history before and after failover.
- Performance and soak-test summaries.

## Release Sign-Off

Release sign-off requires no unresolved Critical defects, complete evidence for
the advertised hardware and vendor scope, secret redaction proof, key-rotation
proof, rollback/recovery proof, HA proof where HA is advertised, and a
successful operator runbook rehearsal.
