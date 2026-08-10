# NAS-0047 Release Certification Checklist

NAS-0047 software implementation is complete when code, migrations, API, UI,
tests, and documentation are merged. The items below are external release
validation and must not block engineering from moving to NAS-0048.

## Software Status

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes

## External Certification / Deployment

- Run FreeRADIUS CoA and Disconnect interoperability on production Linux from a
  standalone node, active HA node, standby node, and runtime-promoted standby.
- Capture packet traces proving standby nodes do not emit RFC 5176 packets until
  HA runtime promotion grants send/replay authority.
- Drill active-to-standby failover with queued CoA and Disconnect records due
  before, during, and after promotion; confirm retry continuity and no duplicate
  packets beyond configured idempotency behavior.
- Drill standby blocking for preview, send, enqueue, retry, and replay and
  retain `/api/v1/system/dac-handoff` plus history evidence.
- Validate fencing-token and lease evidence across process restart, service
  restart, VM reboot, and database restore scenarios.
- Validate Cisco, Aruba, Juniper, Ruckus, Fortinet, MikroTik, Huawei, and H3C
  devices/controllers after failover using direct UDP, proxy UDP, and RadSec
  mTLS delivery paths.
- Run split-brain drills with witness/quorum loss and confirm readiness degrades
  or blocks according to the configured HA policy.
- Run performance, long-duration soak, and queue-replay load tests with active
  and promoted standby nodes.
- Review support bundle redaction and ensure lease/fencing evidence is useful
  without exposing RADIUS shared secrets or unsafe identity selectors.
- Complete security review for cluster role trust, runtime promotion evidence,
  operator authorization, and audit retention.
- Record customer or lab acceptance evidence for every production HA handoff
  claim.
