# NAS-0011 Release Certification Checklist

NAS-0011 engineering is complete when code, automated tests, configuration,
API/UI exposure, documentation, and CI automation are committed. The items below
require real FreeRADIUS deployments, vendor devices, third-party proxies, or
production-like traffic and do not block the next roadmap feature.

## External Validation

- Validate generated `pre-proxy` and `post-proxy` sections with `freeradius -XC`
  on the target Linux release.
- Capture packets showing AegisNAS `Proxy-State` loop markers are added once per
  hop.
- Build a controlled proxy loop and verify marker-based rejection.
- Validate `max_hops` behavior with a chain of proxy peers.
- Verify trusted-source realm rejection for each configured route.
- Verify allowed and denied standard attributes with `radclient` and packet
  capture.
- Verify vendor ID and vendor attribute selectors against real upstream AAA and
  NAS/controller firmware in the release scope.
- Validate `User-Name` rewrite behavior for EAP and non-EAP flows.
- Run accounting proxy tests for start, interim, stop, and malformed accounting
  payloads.
- Run HA upgrade/rollback tests from NAS-0010 to NAS-0011 and back.
- Archive `/api/v1/system/proxy-policy`,
  `/api/v1/system/status`, and `/api/v1/system/production-readiness` output.

## Evidence To Attach

- AegisNAS build SHA and config checksum.
- Generated FreeRADIUS file checksums.
- FreeRADIUS version and OS release.
- Upstream proxy/NAS/controller model, firmware, and topology.
- Packet captures with secrets redacted.
- API JSON for proxy route and proxy policy state.
- Pass/fail notes for loop, trust, deny, allow, rewrite, HA, upgrade, and
  rollback tests.

## Release Decision

Release certification is complete only when every supported route and vendor
profile in the release scope has signed evidence and no unresolved Critical or
High proxy-policy defects remain.
