# NAS-0006 Release Certification Checklist

NAS-0006 software implementation is complete. The items below require external environments, real firmware, third-party releases, lab hardware, security review, or production deployment evidence. They do not block development of NAS-0007.

## Packet And FreeRADIUS Validation

- [ ] Run FreeRADIUS production Linux proxy tests with allowed vendor, vendor-attribute, and standard-type opaque records.
- [ ] Capture packets before and after proxy replay and confirm allowed opaque payloads remain byte-for-byte stable.
- [ ] Confirm malformed vendor lengths, oversized values, disabled policy, and missing allow rules are dropped with deterministic evidence.
- [ ] Confirm `Message-Authenticator`, `EAP-Message`, `User-Password`, `CHAP-Password`, `CHAP-Challenge`, and `Tunnel-Password` are never forwarded through opaque rules.

## Vendor And Firmware Validation

- [ ] Validate at least one long-tail vendor namespace with an allowed unknown VSA and exact model/firmware evidence.
- [ ] Validate one controller correlation-token workflow that needs opaque proxy preservation.
- [ ] Confirm known native mappings are not duplicated through opaque replay unless `allow_known` is deliberately enabled and documented.
- [ ] Attach exact vendor, model, firmware, controller, FreeRADIUS, packet capture, and expected-result evidence to the release record.

## HA And Operations

- [ ] Compare `/api/v1/system/opaque-passthrough` source hashes and effective policy across HA nodes before upgrade and after rollback.
- [ ] Run rolling upgrade, rollback, and split-brain drills while opaque proxy traffic is present.
- [ ] Run long-duration malformed and oversized opaque-packet soak tests and confirm no panic, unbounded memory growth, or silent compatibility claim promotion.
- [ ] Confirm support bundles include policy summaries and SHA-256 evidence only, without raw opaque payloads.

## Security And Governance

- [ ] Review allowlist ownership, change approval, and `allow_known` use for every production rule.
- [ ] Fuzz standard and vendor pass-through collection/replay paths.
- [ ] Confirm product documentation does not represent governed pass-through as native feature implementation or vendor certification.
- [ ] Record customer acceptance evidence for deployments that rely on opaque pass-through to preserve upstream attributes.
