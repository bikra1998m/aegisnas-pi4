# Current implementation audit

**PASS: implemented admission sequence guard. Partial: whole NAS-0116.** This work extends the existing admission implementation; it does not recreate the project or replace inherited changes.

The required state directory binds repository, architecture, state ID, highest verified sequence, exact archive hash and source commit. Explicit initialization refuses an existing directory. Missing/malformed/wrong-scope state and unsafe POSIX permissions or links are rejected. The policy and destination parent are checked as trusted paths. Lexical `..` paths are normalized before checking that state and payload directories are disjoint.

An OS lock spans verification and publication. It prevents concurrent admissions and releases on process death. Verified payload files/directories are flushed first; an atomic, flushed reservation is then written before rename into the absent final destination. A failed publication consumes the sequence. Only the exact same artifact may retry that sequence, with fresh signature/evidence checks; lower sequences and replacement artifacts are rejected. Existing destinations are never overwritten. A receipt records the reservation identity. The stored counter protects admission, not activation or a whole-disk rollback by an administrator.

Tests exercise actual files, locks, subprocess termination, interrupted publication before/after rename, CLI initialization, state corruption, policy lowering, sequence collisions and I/O errors. Unit fixtures mock GitHub verification and scanner success; they do not claim trusted-signature certification. Production path ownership/directory durability is Linux-specific; Windows tests cover logic/locks. Linux tests use an isolated administrative user, not production state. Actual power-loss, NFS semantics and TPM-backed monotonicity are NOT TESTED.

| File changed in this continuation | Change |
|---|---|
| `.github/workflows/release-candidate.yml` | Updated |
| `README.md` | Updated |
| `docs/enterprise-nas-master-implementation-roadmap.md` | Updated |
| `docs/nas-0116-release-certification-checklist.md` | Updated |
| `docs/release-admission-runbook.md` | Updated |
| `docs/supply-chain-release-security.md` | Updated |
| `scripts/admit_release.py` | Updated |
| `scripts/release_sequence.py` | New |
| `scripts/test_admit_release.py` | Updated |

The workflow initializes separate state for each platform on its disposable test runner and passes it to admission. This runner state is not an appliance's durable floor. All production admissions must reuse the appliance's existing protected store. The runbook replaces its earlier policy-floor rollback advice: lowering policy cannot erase the durable reservation; recovery needs a new reviewed, signed, passing candidate with a higher sequence. Existing installed releases need an audited initial floor above their highest prior sequence.

Build/verification: all 11 Python files parse; the release workflow parses using the already installed Playwright YAML implementation, 2 embedded Python blocks parse, and 7 shell blocks pass `bash -n` on Ubuntu. Local PyYAML was absent; no dependency was installed for validation. Normal `git diff --check` passes. Go/TypeScript source and dependency inputs are unchanged, so builds and application suites were retained from the earlier verified epoch rather than rerun. CI hosted execution remains NOT TESTED.

Failures preserved: initial Windows fsync used a read-only descriptor and failed; corrected to a writable descriptor. Ubuntu's umask 0002 produced a 0664 fixture policy that was correctly rejected; fixtures and CI now explicitly set 0600. A quality harness initially expected 3 inline Python blocks rather than the actual 2; corrected without changing workflow behavior. An ad hoc Git check with `core.autocrlf=false` treated repository CRLF as whitespace; the repository-configured check passes. No source line endings were mass-rewritten.

Exact before/after hashes: [changes CSV](2026-10-23-admission-sequence-changes.csv). Full inherited/local Git state: [source state](2026-10-23-admission-sequence-source-state.json). Existing reports and raw evidence remain intact.
