# NAS-0081 Release Certification Checklist

Software implementation is complete when code, tests, docs, APIs, UI, config,
and CI pass. The following items are external certification and deployment
activities and do not block engineering closure.

## External Certification

- [ ] IANA/PEN and published compatibility scope are current for the release.
- [ ] FreeRADIUS interoperability is validated on the production Linux target.
- [ ] RFC 8910 API is observed from Windows, macOS, iOS, Android, ChromeOS, and
  common Linux supplicants.
- [ ] DHCP/RA captive portal option advertisement is packet-capture verified
  where deployed.
- [ ] HTTPS certificate chain, hostname, revocation, and client trust behavior
  are validated.
- [ ] Cisco controller CWA redirect and post-auth CoA are tested for the named
  controller/AP firmware scope.
- [ ] Aruba/HPE controller CWA redirect and post-auth CoA are tested for the
  named controller/AP firmware scope.
- [ ] Ruckus, Fortinet, Meraki, UniFi, Mist, Cambium, MikroTik, OpenWiFi, and
  hostapd scopes are tested or explicitly marked not certified.
- [ ] Walled-garden DNS, FQDN, host, URL, and controller ACL behavior are packet
  capture verified.
- [ ] Post-auth CoA and fail-closed Disconnect behavior are validated with
  positive and negative tests.
- [ ] HA failover preserves portal session evidence and does not duplicate
  post-auth CoA.
- [ ] Performance, scale, soak, and resource-tier limits are measured.
- [ ] Security review covers open redirect, session fixation, replay, CSRF,
  logging redaction, TLS, and controller credential handling.
- [ ] Production deployment and customer acceptance evidence are attached.

## Release Evidence

- [ ] `/api/v1/system/cwa-portal-lifecycle` capture.
- [ ] `/api/v1/system/cwa-portal-lifecycle/history` capture.
- [ ] `/api/v1/system/status` capture with `wireless.cwa_portal_lifecycle`.
- [ ] `/api/v1/system/production-readiness` capture with
  `cwa_portal_lifecycle`.
- [ ] Support bundle containing `api/cwa-portal-lifecycle.json` and
  `api/cwa-portal-lifecycle-history.json`.
- [ ] Controller/AP product and firmware matrix.
- [ ] Packet captures for RFC 8910, redirect, RADIUS Access-Accept, Accounting,
  CoA, CoA-ACK/NAK, and Disconnect where applicable.
