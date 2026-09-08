# NAS-0073 Release Certification Checklist

Engineering implementation status: complete when code, migrations, APIs, UI,
tests, automation, and documentation pass.

Ready for external validation: yes.

Use this checklist before publishing a hardware-certified or customer-certified
claim for an out-of-corpus vendor dictionary.

## External Dictionary Evidence

- [ ] Authoritative source URL, repository tag, or signed vendor package is
  attached.
- [ ] SHA-256 of the exact dictionary text matches the recorded intake event.
- [ ] License or written grant permits product use and distribution.
- [ ] IANA PEN record or vendor-published PEN evidence is attached.
- [ ] Product families, controller versions, firmware versions, and dictionary
  version are recorded.
- [ ] Intake event from `/api/v1/system/external-vendor-intake/record` is
  attached with fingerprint and actor.

## FreeRADIUS Interoperability

- [ ] Dictionary imports cleanly on the target FreeRADIUS production Linux
  baseline.
- [ ] Golden Access-Request, Access-Accept, Access-Reject, Accounting-Request,
  CoA, and Disconnect vectors are replayed where applicable.
- [ ] Packet captures confirm VSA vendor ID, type, length, value encoding, and
  unknown-attribute behavior.
- [ ] Negative vectors cover malformed length, duplicate attributes, invalid
  enum values, oversized payloads, and unknown types.

## Vendor Hardware Or Controller Validation

- [ ] At least one real vendor NAS, AP, switch, gateway, BNG, controller, or
  simulator matching the declared product family is tested.
- [ ] Authentication behavior is verified for supported methods.
- [ ] Authorization behavior is verified for role, VLAN, ACL, bandwidth,
  portal, posture, tenant, route, and subscriber semantics represented by the
  dictionary.
- [ ] Accounting behavior is verified for session identity, counters, interim
  updates, stop reasons, and vendor-specific records.
- [ ] CoA/Disconnect behavior is verified where the vendor supports dynamic
  authorization.
- [ ] Device firmware, controller version, topology, and packet captures are
  attached.

## HA, Upgrade, And Recovery

- [ ] Active/standby nodes preserve intake history and fingerprints.
- [ ] Upgrade from the prior release preserves `external_vendor_intake_events`.
- [ ] Rollback restores the previous binary and leaves recorded evidence
  readable.
- [ ] Replay of recorded intake evidence is deterministic after upgrade.

## Performance And Soak

- [ ] Intake APIs enforce size limits under concurrent submissions.
- [ ] Packet decoding remains bounded for the external vendor attributes.
- [ ] Long-duration authentication/accounting soak shows no leak or unbounded
  storage growth.
- [ ] Metrics and support bundles remain available during load.

## Security And Compliance

- [ ] Secret-like attributes are redacted in UI, API, logs, support bundles, and
  evidence exports.
- [ ] Admin RBAC is verified for read-only, ops, and super-admin roles.
- [ ] Audit logs contain actor, timestamp, source hash, dictionary hash, and
  fingerprint.
- [ ] Security review signs off on source trust, license, malicious dictionary
  content, oversized payloads, and sensitive evidence handling.
- [ ] Customer acceptance or compliance artifact is attached when required.
