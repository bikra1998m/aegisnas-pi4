# NAS-0097 Release Certification Checklist

Engineering implementation is complete. This checklist tracks external release
certification evidence only.

- [ ] Validate FreeRADIUS production Linux interoperability with CableLabs
  dictionaries and captured Access-Request, Access-Accept, Accounting, CoA, and
  Disconnect packets.
- [ ] Validate at least one CMTS and cable modem pair with exact product,
  firmware, DOCSIS version, and supported feature scope.
- [ ] Validate DOCSIS provisioning integration for configured modem profiles,
  service tiers, and provisioning classes.
- [ ] Validate IPDR mediation and downstream billing reconciliation for
  configured charging policies.
- [ ] Validate quota exhaustion and policy-update behavior through CoA or
  Disconnect where supported by the CMTS.
- [ ] Validate HA failover and replay for `docsis_policy_events` and
  `docsis_policy_profiles`.
- [ ] Run scale, latency, malformed-packet, replay, rollback, and soak tests for
  the release candidate.
- [ ] Attach support bundle evidence containing `api/docsis-policy.json` and
  `api/docsis-policy-history.json`.
- [ ] Attach production readiness and system status reports with
  `docsis_policy_charging` not blocked.
- [ ] Complete security review for privacy-safe device identifiers, IPDR export
  data handling, and operator permissions.
