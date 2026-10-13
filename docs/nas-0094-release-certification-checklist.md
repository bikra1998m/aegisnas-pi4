# NAS-0094 Release Certification Checklist

NAS-0094 software engineering is complete when the code, schema, APIs, UI,
configuration, documentation, automation, and automated tests pass. The items
below require external systems, real hardware, third-party environments, or
long-duration proof and do not block closing the engineering roadmap item.

## Software Completion

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes
- Feature ID: NAS-0094
- Feature: Mobile online/offline charging correlation
- Runtime component: `mobile_charging_correlation`
- Schema: v98

## External Certification / Deployment

- [ ] IANA/vendor identity review for customer-facing release notes.
- [ ] FreeRADIUS production Linux interoperability using current dictionaries.
- [ ] Live OCS simulator proof for online charging quota grant, interim usage,
  threshold crossing, exhaustion, CoA, and disconnect behavior.
- [ ] Live OFCS simulator proof for offline CDR export, batch integrity,
  duplicate suppression, late Stop handling, and reconciliation.
- [ ] Carrier mediation proof for JSONL export, manifest hash, redaction,
  subscriber hash stability, replay, and downstream acknowledgement.
- [ ] Rating-group proof for APN, service identifier, unit, currency, and
  quota-policy mapping.
- [ ] Quota-policy proof for octet and event grants, threshold actions,
  validity windows, restrict/quarantine/disconnect behavior, and retry safety.
- [ ] Starent/Cisco ASR product and firmware matrix evidence.
- [ ] Ericsson/Redback and Ericsson packet-core product and firmware matrix
  evidence.
- [ ] 3GPP and 3GPP2 dictionary attribute packet captures with redacted
  subscriber identifiers and retained deterministic hashes.
- [ ] WiMAX charging-session capture when WiMAX support is in release scope.
- [ ] HA active/standby replay proof using
  `mobile_charging_correlation_events` and
  `mobile_charging_correlation_profiles`.
- [ ] Upgrade and rollback proof from the previous production release.
- [ ] Scale benchmark for configured `mobile.charging.event_retention_limit`
  and expected CDR/export volume.
- [ ] Long-duration soak with interim accounting, quota updates, and CoA churn.
- [ ] Security audit for subscriber identifier redaction, hashing, support
  bundles, API authorization, export retention, and mediation handoff.
- [ ] Customer acceptance evidence for the exact vendor/product/firmware scope.

## Required Evidence Artifacts

- `/api/v1/system/mobile-charging` response.
- `/api/v1/system/mobile-charging/history` response.
- Support bundle containing `api/mobile-charging.json` and
  `api/mobile-charging-history.json`.
- OCS, OFCS, mediation, FreeRADIUS, and packet-core packet captures with
  subscriber identifiers redacted or hashed.
- FreeRADIUS dictionary version and SHA evidence.
- HA failover, upgrade, rollback, scale, soak, and security reports.
