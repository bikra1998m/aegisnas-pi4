# NAS-0116 implementation and release checklist

Engineering status: **Partial**. This checklist includes remaining software work
as well as external evidence; none of the unchecked items is completed by plan.

- [x] Add Go/npm dependency inventories and local evidence capture.
- [x] Implement fail-closed scan-result and evidence-integrity checks.
- [x] Add negative tests for failed, missing, malformed, stale and tampered evidence.
  October 29 follow-up rejects non-integer dependency, npm and OS report schema
  versions, with failing reproductions retained separately from successful reruns.
- [x] Add candidate build, provenance/SBOM attestation and verification workflow.
- [x] Route both expected signed CI candidates through policy-bound admission before uploading them; retain receipts. Workflow execution remains unchecked below.
- [x] Add non-waiving comparison of scanner findings with shipped command imports for both Linux targets.
- [ ] Execute a passing end-to-end trusted workflow on an actual candidate.
- [x] Remediate all blocking dependency findings or approve a governed policy change.
  November 5: Go AMD64/ARM64 package scans are clear after the official crypto
  module split, and npm audit is clear after the follow-redirects patch. A fresh
  complete committed-source dependency gate now passes on `0578d45158454b707d0f41ab669741c47343ad84`; no policy waiver is used.
- [ ] Verify a real signed candidate and reject a tampered copy.
- [x] Add verified candidate staging with signature admission, payload integrity and downgrade tests.
- [x] Add full staged-payload re-verification against the original signed archive, current policy and existing sequence reservation; fix group-writable publication permissions and reject later unsafe changes. See [re-verification](release-reverification.md). Local positive signature checks remain mocks; the trusted hosted execution item is still open.
- [x] Persist verified sequence/artifact reservations before staging publication; reject downgrade and sequence reuse across invocations, serialize admissions, and test process-exit/I/O-failure recovery on Windows and Ubuntu. Windows does not certify Linux directory durability or permissions.
- [x] Implement a separate encrypted SQLite recovery snapshot and authenticated staging path, with strict archive bounds and no unsigned fallback. See [scope and limitations](authenticated-recovery-staging.md).
- [ ] Integrate admission and authenticated recovery with production activation and every database/config restore entry point; validate coordinated rollback and power-loss behavior.
  November 5 legacy CLI repairs add WAL-consistent SQLite backups, strict bounded
  archive/manifest validation, PostgreSQL rejection, offline sidecar guards and
  staged replacement with ordinary I/O-failure compensation. Actual Windows and
  Ubuntu fixture results are recorded in the [recovery report](reports/2026-11-05-recovery-cli-readiness.md).
  Checksums still do not authenticate these archives; this acceptance item stays open.
- [x] Add pinned OS/rootfs and OCI-archive inventories and vulnerability gate commands.
- [x] Add bounded read-only inventories of snap blobs, firmware and boot files, with independent-digest comparison and fail-closed coverage status. See [artifact inventory](appliance-artifact-inventory.md).
- [ ] Complete nested snap package inventories/scans, firmware advisory mapping and artifact-to-image binding, then execute signed full-image workflows. File hashes alone do not close this gate.
- [ ] Implement approved exception lifecycle, remediation SLA and audit retention.
- [x] Expose accurate installed-admission state in admin API/UI and support bundles with authorization tests.
- [x] Add reproducible isolated real API/SQLite/support-bundle tests and HTTP latency measurement.
- [ ] Complete builder/security review, release permission review and recovery drills.

See [supply-chain-release-security.md](supply-chain-release-security.md).
Current evidence and blockers: [November 5 hosted and OS validation](reports/2026-11-05-roadmap-github-security-final.md).
