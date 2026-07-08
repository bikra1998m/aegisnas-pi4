# NAS-0002 Release Certification Checklist

Feature: `NAS-0002` - Generated typed attribute registry

Engineering status: complete

These external activities gate a certified release and do not reopen NAS-0002 engineering work.

## FreeRADIUS interoperability

- [ ] Regenerate the source audit from an independently obtained FreeRADIUS 3.2.8 source archive.
- [ ] Verify all 246 dictionary files and the source archive signature/checksum.
- [ ] Compare all 7,654 source records, aliases, types, options, and enumerations on supported Linux releases.
- [ ] Run FreeRADIUS configuration validation with every enabled compatibility pack.
- [ ] Archive the source manifest, registry SHA-256, generated diff, and reviewer approval.

## Vendor hardware

- [ ] Test every executable registry mapping against its declared vendor/model/firmware scope.
- [ ] Capture representative Access, Accounting, CoA, and Disconnect packets.
- [ ] Verify alias collisions and repeated attributes on real peers.
- [ ] Record unsupported, ignored, and firmware-dependent behavior without promoting mapping status.

## HA and deployment

- [ ] Prove active and standby nodes reject mixed registry hashes.
- [ ] Validate rolling upgrade and rollback between registry-bearing releases.
- [ ] Validate backup/restore and disaster recovery with stable registry references.

## Performance and endurance

- [ ] Benchmark startup parsing, PEN/number lookup, vendor/name lookup, API filtering, and pagination at release limits.
- [ ] Run long-duration packet and API soak tests with all compatibility packs represented.
- [ ] Confirm memory, latency, and binary-size budgets on Lite, Branch, and Enterprise hardware.

## Security and acceptance

- [ ] Complete independent parser, generator, API pagination, and supply-chain review.
- [ ] Fuzz malformed dictionaries and registry CSV inputs using the release toolchain.
- [ ] Complete customer-environment acceptance tests and required compliance review.
- [ ] Attach all evidence to the release record and obtain release sign-off.

## Release gate

A release may claim certified registry interoperability only when every applicable item is complete, all cluster nodes report the approved source hash, and no unresolved Critical defect remains.
