# NAS-0116 completion and gap report

**Engineering: Partial. Security gate: BLOCKED. Release candidate readiness: NO.** No feature was closed by treating a plan, mock signature or successful scan command as production evidence.

## Implemented and verified scope

The earlier continuation implemented locked Go/npm upgrades, complete dependency inventories, dual-target package/test vulnerability scans, evidence freshness/integrity checks, pinned release workflow actions, dual provenance/SBOM verification, bounded archive extraction, policy-bound release staging, downgrade/platform/source checks, admission API/UI/support-bundle visibility and OS/rootfs scanning. Its source and raw evidence remain preserved.

This reconciliation adds:

- `scripts/analyze_go_exposure.py`: integrity-checked comparison of saved Go findings with newly collected imports for all shipped command packages on Linux AMD64/ARM64, CGO disabled. It records distinct scanner and analysis snapshots, dependency fingerprints and raw graph hashes. Eight new negative/positive tests ensure missing metadata stays unknown and imported packages are not called reachable symbols. It cannot approve or waive a release gate.
- `.github/workflows/release-candidate.yml`: the trusted signing job requires exactly the AMD64 and ARM64 archives and calls the same admission implementation used by operators. The runner supplies repository, source allowlist, platform and minimum sequence; the archive cannot choose its own policy. Receipts accompany the verified artifact upload. No deployment is performed.
- Historical reconciliation and corrected roadmap/checklist claims. The conservative vulnerability policy is unchanged.

## Acceptance status

| Area | Status | Evidence / limit |
|---|---|---|
| Corrected Go scans | PASS execution / BLOCKED policy | Earlier complete scans cover all packages/tests for both targets, all collector commands exit zero, hashes retained. GO-2026-5932 remains blocking. New import analysis does not replace a fresh final-candidate scan. |
| Complete npm dependency inventory | PASS | 184 CycloneDX components, lockfile including development dependencies; earlier optional-package inventory failure retained. Captured npm audit has zero vulnerabilities. |
| OS package evidence | PASS collection / BLOCKED policy | Unchanged VM dpkg/os-release hashes; 4,236 blocking package/advisory occurrences, 537 unique IDs. No OS remediation or service interruption performed. |
| Trusted signing implementation | PASS local fixture/static scope | Workflow/action pins and verification arguments exist. Actual signing job has **NOT TESTED** status. |
| Actual signed artifact admission/tamper | BLOCKED | No trusted candidate/attestations available; GitHub CLI absent and GitHub connector unauthenticated. Fixture admission tests are explicitly not cryptographic proof. |
| Version/downgrade protection | PASS bounded staging tests | Trusted repository/commit/platform and monotonic minimum sequence checked. Production storage, advancement and recovery of that floor are unfinished activation work. |
| API/UI integration | PASS earlier UI and real API scope | Release Security is an authenticated observation surface. A stored receipt is not represented as fresh signature verification. New focused DB/API regressions are in the regression reports. |
| PostgreSQL | PASS tested slice / Partial overall | Migration/seed/audit/rollback plus newly repaired NAS-client lifecycle on actual PostgreSQL 18.6 and 14.24. Other services remain unverified/incompatible. |
| CI wiring | PASS static / NOT TESTED hosted execution | Ten release-workflow actions pinned; two embedded Python blocks compile; signing depends on evidence and is restricted to manual main. New policy-bound admission step cannot be executed here without a trusted signed candidate. |
| Production activation and rollback | NOT TESTED / software incomplete | Staging intentionally does not replace binaries, migrate a deployed database, stop services or activate a release. See below. |
| Snap/firmware/full-image certification | NOT TESTED | Snap name/revision listing is not content scanning. No signed production image, firmware manifest or target Pi certification environment supplied. |

## Remaining software work

1. Integrate admission with a serialized, root-owned activation transaction: trusted policy ownership, monotonic sequence persistence, binary/config/schema compatibility, admission recheck before activation, bounded health checks and durable state/audit evidence.
2. Authenticate database/config recovery packages and implement failure compensation. Review of `scripts/ubuntu-upgrade-rollback-restore.sh` found backups taken before service quiescence, ignored service-stop failures and no complete failure-recovery transaction. Its syntax check passes; its apply path was **NOT TESTED** and is not a certified activation path. No deployed data was touched.
3. Integrate full-image OS, snap and firmware inventories with artifact identity and the release gate. The current application archive workflow is not whole-appliance certification.
4. Implement approved exception lifecycle, expiry, audit retention and remediation SLAs only after a documented policy is supplied. There is currently no exception that can silently bypass the conservative Go gate.
5. Expand independent builder, permission, rollback and negative-path review; automate PostgreSQL service-wide integration coverage rather than relying only on optional local DSN tests.

## External prerequisites

- Reviewed, committed source and workflow; explicit authorization before any push or hosted publishing action. Local and remote main still point to `7004511cfbea5f30d53db9b6ac768e059d7cfaf1`.
- Passing conservative application and applicable image gates, a protected trusted main environment with attestation permissions, and an authenticated supported GitHub verifier. Repository branch-protection settings were **NOT TESTED** because the connector is not connected.
- For Ubuntu Core images, registered signing identity/key and the intended model/store setup. No fake signature was generated.
- Target Pi/production OS hardware, recovery environment, real vendor/RadSec/telecom peers and certification owners.

NAS-0008 is the next unfinished dependency-ordered item after NAS-0116. The independent NAS-client compatibility slice was advanced without declaring NAS-0116 complete or unlocking NAS-0099 consensus work. See the [readiness assessment](2026-10-15-reconciliation-readiness.md).
