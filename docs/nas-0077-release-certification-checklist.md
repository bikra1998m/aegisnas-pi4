# NAS-0077 Release Certification Checklist

NAS-0077 software engineering is complete when code, configuration, database,
API, UI, tests, documentation, automation, and CI are merged. The items below
are external release evidence and must not block the next roadmap feature.

## Software Status

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes
- Feature: DPSK and PPSK lifecycle
- Release owner: AegisNAS release engineering

## External Certification / Deployment

- [ ] IANA/vendor identity records are correct in the release artifact.
- [ ] FreeRADIUS interoperability is validated on the supported production
      Linux distribution.
- [ ] hostapd WPA2 personal PPSK config is validated on supported physical
      radio hardware.
- [ ] Managed `wpa_psk_file` permissions, reload behavior, and client join
      behavior are validated on the supported appliance image.
- [ ] Packet captures prove successful joins for active PPSK credentials and
      failed joins for revoked, expired, missing, or wrong-MAC credentials.
- [ ] Ruckus DPSK, Aruba MPSK, Cisco private PSK, UniFi PPSK, and Cambium PPSK
      behavior is certified only for the published controller/AP firmware
      versions.
- [ ] Controller API push/pull, drift detection, retries, and rollback are
      validated in each supported controller environment before controller-sync
      claims are published.
- [ ] CoA/Disconnect behavior after PPSK revocation is validated where the
      release scope claims active session removal.
- [ ] HA active/standby failover is tested during preview and apply.
- [ ] Upgrade and rollback drills preserve lifecycle history and generated
      hostapd/PPSK output.
- [ ] Performance benchmarks cover large credential lists and high-frequency
      preview operations.
- [ ] Long-duration soak testing covers hostapd restarts, client joins,
      credential rotation windows, accounting, and revocation workflows.
- [ ] Security review confirms no PSK secrets leak through API, UI, logs,
      support bundles, lifecycle history, crash dumps, or generated diagnostics.
- [ ] Production deployment runbook is executed in a representative
      environment.
- [ ] Customer acceptance testing signs off exact AP/client/controller/firmware
      support claims.

## Evidence To Attach

- Hostapd config diff, PPSK file fingerprint, and plan fingerprint.
- Packet captures for association, four-way handshake, RADIUS Access,
  Accounting, and CoA/Disconnect paths used in the release scope.
- Client join logs for supported operating systems and device classes.
- FreeRADIUS debug logs for supported authorization/accounting flows.
- Controller/AP firmware inventory and configuration export.
- Credential rotation and revocation transcript.
- HA failover transcript.
- Performance and soak reports.
- Security audit findings and remediation proof.
- Signed release acceptance record.
