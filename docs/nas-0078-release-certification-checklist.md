# NAS-0078 Release Certification Checklist

Feature: Controller estate and object lifecycle

Software Implementation: 100% Complete
Engineering Implementation: 100% Complete
Ready for External Validation: Yes

## External Certification / Deployment

- [ ] Validate controller estate preview against Cisco controller firmware and
  API versions in the release matrix.
- [ ] Validate controller estate preview against Aruba Central or HPE Aruba
  controller firmware and API versions in the release matrix.
- [ ] Validate controller estate preview against Juniper Mist, Ruckus,
  Fortinet, MikroTik, UniFi, Meraki, and TIP OpenWiFi versions in scope.
- [ ] Capture packet/API traces proving redacted credential handling and
  desired-state hash correlation.
- [ ] Reconcile real AP, site, WLAN, RADIUS profile, guest portal, roaming,
  Passpoint, PPSK, and bandwidth objects against controller inventory.
- [ ] Prove delete guards prevent automatic removal of unknown or orphaned
  controller objects.
- [ ] Prove rollback checkpoint evidence is available before and after
  controller sync operations.
- [ ] Execute HA failover while controller lifecycle preview/apply/history are
  active.
- [ ] Execute controller API outage, rate-limit, authentication failure, and
  partial-response drills.
- [ ] Run performance, scale, and long-duration soak tests for the largest
  supported controller estate.
- [ ] Complete security audit for API tokens, environment references, support
  bundles, logs, and UI rendering.
- [ ] Complete production deployment and customer acceptance evidence.

These activities are required for release certification and customer claims, but
they do not keep NAS-0078 engineering open.
