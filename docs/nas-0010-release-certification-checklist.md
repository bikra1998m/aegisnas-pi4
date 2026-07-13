# NAS-0010 Release Certification Checklist

NAS-0010 engineering is complete when software, tests, automation, and
documentation are merged. The items below require real infrastructure, vendor
hardware, third-party systems, or production-like deployment and do not block the
next roadmap feature.

## External Validation

- Run generated `proxy.conf`, `sites-enabled/default`, and
  `sites-enabled/inner-tunnel` on production Linux with FreeRADIUS.
- Validate `radclient` Access-Request and Accounting-Request routing for every
  configured route and alias.
- Capture packets proving explicit realm routing, default route routing,
  realm-less `NULL` routing, and no-route local handling.
- Test upstream outage behavior for fail-over, load-balance, and status-server
  disabled routes.
- Verify shared-secret and RadSec upstream paths with production-grade secrets
  and certificates.
- Run vendor-device smoke tests for APs, switches, controllers, and federation
  proxies in the release scope.
- Validate HA behavior with both active and standby nodes generating identical
  route tables.
- Run upgrade and rollback from the previous single-realm version to the
  multi-route version.
- Perform scale testing for expected route count, home-server count, and
  per-route accounting volume.
- Archive API output from `/api/v1/system/proxy-routes`,
  `/api/v1/system/status`, and `/api/v1/system/production-readiness`.

## Evidence To Attach

- AegisNAS build SHA and config checksum.
- Generated FreeRADIUS file checksums.
- FreeRADIUS version and OS release.
- Vendor model, firmware, controller version, and topology.
- Packet captures with secrets redacted.
- Route table API JSON.
- Readiness report JSON.
- Test timestamps, operator name, and pass/fail notes.

## Release Decision

Release certification is complete only when all supported deployment profiles in
the release scope have signed evidence and no unresolved Critical or High
interoperability defects remain.
