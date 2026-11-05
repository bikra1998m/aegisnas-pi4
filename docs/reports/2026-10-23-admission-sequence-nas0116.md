# NAS-0116 completion and remaining gaps

**Status: Partial. Release candidate and production activation: BLOCKED.**

Implemented and tested in this continuation: mandatory persistent sequence state; repository/platform binding; no downgrade after lowering policy; same-sequence collision rejection; OS interprocess lock; flushed reservation before publication; identical-artifact recovery with full reverification; fail-closed missing/corrupt/unsafe state; explicit initialization and runbook/CI integration. Windows 47 PASS/1 SKIPPED; Ubuntu 48 PASS. These close the admission persistence gap, not the milestone.

Existing inventory/scanning, artifact signature verification configuration, bounded extraction, commit/architecture binding, read-only API/UI and support-bundle behavior remain intact. API decoding tolerates the added receipt field, but the API does not read or attest to the live private sequence store.

Still required:

1. Resolve blocking dependency and OS findings, or implement a separately reviewed evidence-based exception lifecycle with owners, expiry, revocation and audit. No such exception is approved here.
2. Obtain an approved clean source commit and execute trusted main-branch hosted signing with GitHub OIDC/attestation permissions; verify a real candidate and tampered copy. Current read-only GitHub access is not proof of those permissions.
3. Implement coordinated production activation, database/config migration, authenticated/encrypted recovery data and rollback integration across every installer/update/image/snap entrypoint. Admission currently stages only. Source-build lab scripts remain lab workflows.
4. Complete immutable full-image/snap/firmware inventory and image-specific signing/security evidence.
5. Approve governance: release approvers, vulnerability ownership/remediation SLA, incident/recovery policy, retention, protected branch/release controls and independent builder/security assessment.
6. Certify actual power-loss and deployment recovery, supported filesystems and customer/hardware environments. Unit process exits and I/O injection are narrower evidence.

The successful-milestone condition for commit/push is unmet. No staging, commit, push or production replacement occurred. Dirty-tree requirements alone are not the reason: substantive security/activation gaps remain. Completing an admission subcomponent does not justify marking all NAS-0116 gates or 135 milestones passed.
