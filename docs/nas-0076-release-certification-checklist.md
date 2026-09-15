# NAS-0076 Release Certification Checklist

NAS-0076 software engineering is complete when code, configuration, database,
API, UI, tests, documentation, automation, and CI are merged. The items below
are external release evidence and must not block the next roadmap feature.

## Software Status

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes
- Feature: Passpoint and Hotspot 2.0 lifecycle
- Release owner: AegisNAS release engineering

## External Certification / Deployment

- [ ] IANA/vendor identity records are correct in the release artifact.
- [ ] FreeRADIUS interoperability is validated on the supported production
      Linux distribution.
- [ ] hostapd Passpoint and Hotspot 2.0 config is validated on supported
      physical radio hardware.
- [ ] ANQP packet captures show expected domain name, roaming consortium OI,
      NAI realm, 3GPP cellular, WAN metrics, connection capability, venue, and
      operator metadata.
- [ ] Hotspot 2.0 OSU metadata is validated with supported client platforms.
- [ ] EAP-TLS, EAP-TTLS, EAP-SIM, EAP-AKA, and EAP-AKA' client behavior is
      validated where each credential type is claimed.
- [ ] WISPr, ChilliSpot, Nomadix, and captive portal interoperability is tested
      only for the published release scope.
- [ ] Roaming consortium and carrier offload behavior is validated with the
      actual roaming partner or clearinghouse before any commercial claim.
- [ ] Controller-managed AP behavior is certified separately for each supported
      controller and firmware version.
- [ ] HA active/standby failover is tested during preview and apply.
- [ ] Upgrade and rollback drills preserve lifecycle history and generated
      hostapd output.
- [ ] Performance benchmarks cover large profile lists and high-frequency
      preview operations.
- [ ] Long-duration soak testing covers hostapd restarts, client joins, and
      accounting flows.
- [ ] Security review confirms no secrets leak through API, UI, logs, support
      bundles, or lifecycle history.
- [ ] Production deployment runbook is executed in a representative
      environment.
- [ ] Customer acceptance testing signs off exact AP/client/controller/firmware
      support claims.

## Evidence To Attach

- Hostapd config diff and SHA-256 fingerprint.
- Packet captures for ANQP, EAP, RADIUS Access, Accounting, CoA, and portal
  redirect paths used in the release scope.
- Client join logs for supported operating systems.
- FreeRADIUS debug logs for supported EAP methods.
- Controller/AP firmware inventory and configuration export.
- HA failover transcript.
- Performance and soak reports.
- Security audit findings and remediation proof.
- Signed release acceptance record.
