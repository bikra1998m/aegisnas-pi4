# NAS-0046 Release Certification Checklist

NAS-0046 software implementation is complete when code, migrations, API, UI,
tests, and documentation are merged. The items below are external release
validation and must not block engineering from moving to NAS-0047.

## Software Status

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes

## External Certification / Deployment

- Run FreeRADIUS CoA and Disconnect interoperability on production Linux with
  session-owned target resolution and conflicting-target rejection captured.
- Capture packet traces proving Message-Authenticator, selectors, standard
  attributes, vendor VSAs, ACK, NAK, and Error-Cause behavior still match RFC
  5176 after ownership enrichment.
- Validate Cisco, Aruba, Juniper, Ruckus, Fortinet, MikroTik, Huawei, and H3C
  devices/controllers with active session ownership, stale ownership, and
  unknown ownership cases.
- Drill direct UDP, proxy UDP, and RadSec proxy paths with `ownership_decision`
  evidence in preview, send, queue, replay, history, and support bundles.
- Validate HA/failover behavior with the current active/standby topology, then
  repeat after NAS-0047 cluster handoff work lands.
- Run performance and soak tests with high active-session counts and bounded
  `/api/v1/system/nas-ownership` response sizes.
- Review support bundle redaction and ensure identity selectors remain hashed or
  absent while owner/capability evidence is sufficient for troubleshooting.
- Complete security review for capability JSON trust boundaries and operator
  authorization around outbound DAC send/enqueue.
- Record customer or lab acceptance evidence for every production claim.
