# NAS-0093 Release Certification Checklist

NAS-0093 software engineering is complete when the code, schema, APIs, UI,
configuration, documentation, automation, and automated tests pass. The items
below require external systems, real hardware, third-party environments, or
long-duration proof and do not block closing the engineering roadmap item.

## Software Completion

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes
- Feature ID: NAS-0093
- Feature: Mobile session, APN/PDP/bearer state
- Runtime component: `mobile_session_state`
- Schema: v97

## External Certification / Deployment

- [ ] IANA/vendor identity review for customer-facing release notes.
- [ ] FreeRADIUS production Linux interoperability using current dictionaries.
- [ ] Carrier packet-core simulator test for Access-Accept, Accounting-Start,
  Interim-Update, Stop, CoA, and Disconnect flows.
- [ ] APN/PDP/PDN packet captures for IPv4, IPv6, and IPv4v6 sessions.
- [ ] Default bearer and dedicated bearer QoS evidence with QCI, ARP, MBR, GBR,
  and traffic-flow templates.
- [ ] Roaming lab proof for home PLMN, visited PLMN, local breakout, and
  non-local-breakout policy.
- [ ] Handover state proof across RAT changes and accounting updates.
- [ ] Starent/Cisco ASR product and firmware matrix evidence.
- [ ] Ericsson/Redback and Ericsson packet-core product and firmware matrix
  evidence.
- [ ] 3GPP dictionary attribute packet captures with redacted subscriber
  identifiers and retained deterministic hashes.
- [ ] HA active/standby replay proof using `mobile_session_state_events` and
  `mobile_session_state_profiles`.
- [ ] Upgrade and rollback proof from the previous production release.
- [ ] Scale benchmark for configured `mobile.sessions.max_sessions`.
- [ ] Long-duration soak with interim accounting and CoA churn.
- [ ] Security audit for subscriber identifier redaction, hashing, support
  bundles, API authorization, and retention.
- [ ] Customer acceptance evidence for the exact vendor/product/firmware scope.

## Required Evidence Artifacts

- `/api/v1/system/mobile-sessions` response.
- `/api/v1/system/mobile-sessions/history` response.
- Support bundle containing `api/mobile-sessions.json` and
  `api/mobile-sessions-history.json`.
- Packet captures with subscriber identifiers redacted or hashed.
- FreeRADIUS dictionary version and SHA evidence.
- HA failover, upgrade, rollback, scale, soak, and security reports.
