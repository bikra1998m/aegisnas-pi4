# NAS-0004 Release Certification Checklist

NAS-0004 software implementation is complete. The items below require external environments, real firmware, third-party releases, lab hardware, security review, or production deployment evidence. They do not block development of NAS-0005.

## Evidence Publication

- [ ] Review every `software_ready_external_required` record before publishing vendor compatibility claims.
- [ ] Confirm no record is marked `certified` until a signed certification evidence store exists.
- [ ] Archive `/api/v1/system/compatibility-evidence` output with the release candidate.
- [ ] Compare evidence summaries across HA nodes and reject mixed release profile IDs or registry hashes.

## Vendor And Firmware Validation

- [ ] Run real AP, switch, firewall, controller, and BNG smoke tests for every active vendor pack.
- [ ] Attach exact vendor, model, firmware, controller, FreeRADIUS, packet capture, and expected-result evidence to the release record.
- [ ] Re-run certification after firmware, controller, registry, policy renderer, packet codec, HA, or upgrade changes.
- [ ] Record unsupported and not-applicable behavior without promoting software-ready records to certified.

## Operational Validation

- [ ] Validate the evidence endpoint under authenticated read-only, ops, and super-admin roles.
- [ ] Confirm support bundles and release artifacts include evidence summaries without secrets.
- [ ] Perform upgrade and rollback drills and confirm evidence source hashes remain consistent.
- [ ] Run long-duration soak tests for active vendor packs and compare runtime observability counters with static evidence claims.

## Governance

- [ ] Have release engineering approve published wording for `software_ready`, `external_required`, and `certified`.
- [ ] Confirm sales/support documentation does not treat dictionary presence as feature certification.
- [ ] Record customer acceptance evidence for every certified deployment profile.
