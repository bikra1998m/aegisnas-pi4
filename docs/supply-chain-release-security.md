# Supply-chain evidence and release candidates (NAS-0116)

Status: **Partial**. The repository now has executable dependency inventories,
vulnerability gates, candidate packaging, and a trusted-workflow attestation
path. This does not establish production readiness or a SLSA certification.

November 5 remediation pins `golang.org/x/crypto` to upstream commit
`2f1f834330b2` (`v0.58.1-0.20261009181718-2f1f834330b2`). That upstream change
separates the deprecated OpenPGP module from the parent module; it does not make
OpenPGP safe. No OpenPGP dependency is introduced. Both Linux package scans
reported zero findings after this update. The npm lockfile also updates
`follow-redirects` from 1.16.1 to patched 1.16.2. The all-findings Go policy and
high/critical npm gate remain unchanged. See the
[current assessment](reports/2026-11-05-roadmap-readiness.md) for execution dates,
retained failed attempts and remaining release gates.

## Local evidence

For explanatory runtime scope after a completed scan, run:

```sh
python3 scripts/analyze_go_exposure.py --evidence build/security --output build/go-exposure
```

This verifies the saved evidence and unchanged dependency inputs, records fresh
`go list -deps ./cmd/...` graphs for both shipped targets, and compares the
advisory's affected packages with those imports. It does not waive findings,
establish symbol reachability, or replace a fresh scan of a final candidate.
Its graph and scanner source snapshots are separately recorded. Analysis success
is not vulnerability-gate success.

Use Python 3.10+, Go 1.26.10+, npm 10+, and the pinned tools:

```sh
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0
go mod download all
npm ci --prefix web/admin-ui
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/release_security.py scan --output build/security
```

The output directory must be new. Evidence includes CycloneDX inventories for
the Go module (including the standard library) and the npm lockfile (including
development dependencies), raw scanner output, stderr, command exit codes,
durations, source commit/tree/dependency hashes, and a machine-readable gate.
An interrupted, empty, malformed, stale, or failed scan blocks the candidate.
Go module checksum verification must pass. Both Linux AMD64 and ARM64 scans
cover `./...` including test packages with CGO disabled, matching the binary
candidate build targets. The former single-command module scan did not cover
every imported package; it has been replaced. Scanner JSON findings are evaluated
even when the scanner exits zero. A checksum establishes consistency, not
authenticity; `signature_verified` remains false in the offline gate.

Policy:

- Every Go vulnerability finding blocks, including module-level findings that
  may be unreachable. A later reachability exception needs an explicitly
  reviewed policy change; there is no ignore-list or bypass argument.
- npm high and critical findings block, including build dependencies. Lower
  severities remain in the raw audit for review.
- Evidence must be no more than 24 hours old and match the source tree and
  dependency inputs. Release candidates also require a clean committed tree.
- Dependency files must not change during evidence collection or packaging.
- A missing scanner, unavailable advisory service, or failed signature check
  is a blocker, never a clean scan.
- Schema versions must be JSON integers: dependency evidence version 1, npm
  audit version 2 and Trivy report version 2. Boolean, floating-point, string
  and null substitutes are rejected even when their numeric values compare equal.

Scan reports from local dirty development trees are useful diagnostics but
cannot pass `--require-clean`. Run the command again into a new directory after
changing dependencies. Do not overwrite the previous report.

## CI and candidate verification

`.github/workflows/release-candidate.yml` runs the gate, Go tests, UI build and
browser suite. Only a manual run on `main` reaches the signing job. Pull
requests receive no signing permissions. Action implementations are pinned to
full Git commit hashes; scanner versions are pinned. Go and Node patch releases
use the Go patch floor in `go.mod` and Node 22 respectively, and are recorded by
the build and scanner evidence. Bit-for-bit compiler reproducibility is not claimed.

`scripts/build-release-candidate.sh` produces Linux AMD64 and ARM64 archives
with all command binaries, UI assets, source commit, per-file checksums, and
security evidence and a manifest binding repository, source, architecture and
workflow release sequence. These are binary candidates, not complete appliance images
or installers. The combined SBOM inventories the whole module and npm
dependency graph; it is broader than the runtime contents of either archive.

GitHub signs build provenance and CycloneDX SBOM attestations for the archives.
Before uploading the verified candidate, the workflow runs:

```sh
python3 scripts/release_security.py verify aegisnas-linux-arm64.tar.gz \
  --repo bikra1998m/aegisnas-pi4 --commit FULL_EXPECTED_COMMIT_SHA
```

Choose the expected repository and commit from a trusted release record.
Verification requires GitHub CLI and access to the attestation service. It
checks the artifact digest, both predicate types, expected repository,
`release-candidate.yml` identity, `main` source ref, full source commit, and
GitHub-hosted runner requirement. There is no unsigned fallback. Downloaded
checksums alone must never authorize installation. No workflow here publishes
a release or deploys to an appliance.

## Remaining engineering and operational gates

The [authenticated recovery staging guide](authenticated-recovery-staging.md)
adds encrypted SQLite snapshots, key/context/exact-digest verification and
bounded private extraction. This is local recovery-data authentication, not a
release signature. Coordinated production activation remains incomplete, and
legacy raw ZIP recovery paths are not promoted to production entry points.

The [admission runbook](release-admission-runbook.md) describes the executable
signature, checksum, path-safety and downgrade admission checks; read-only API/UI
and support-bundle integration; isolated real API tests; and the separate pinned
Trivy OS/rootfs and OCI-archive scan command. Admission stages a new directory;
it does not activate a deployment.

Admission now requires a protected persistent sequence store. The verified
sequence/artifact reservation is flushed before publishing files; concurrent
admission, lower sequences, same-sequence replacement artifacts, missing state
and unsafe trusted paths fail closed. An interrupted attempt can retry the exact
same archive without resetting the floor. See the runbook for initial provisioning,
permissions and recovery limits. This closes the staging sequence-persistence
gap; it does not implement production activation or authenticated data rollback.

- Execute the complete workflow on the trusted repository, retain its signed
  bundles and verification results, and test a tampered real artifact.
- Integrate staged admission with every production installer, image, snap,
  upgrade and rollback activation entry point. Lab source-build scripts are
  **not** retroactively gated; local database/config recovery packages require
  separate authentication and coordination with binary rollback.
- Cover base OS, system packages, FreeRADIUS and snap/image dependencies in
  signed image-specific inventories. The separate OS scanner now inventories
  rootfs/OCI OS packages. [File inventories](appliance-artifact-inventory.md)
  now cover installed snap blobs, firmware and boot files with explicit bounds
  and digest comparison; nested snap package scans and firmware advisory
  mapping still need coverage. File hashes never waive those requirements.
- Define and approve vulnerability ownership, remediation deadlines, exception
  approvals/expiry, incident response, and retention policy. No SLA is implied.
- Add governed exception audit history. Release admission state is now present
  in the API/UI/support bundle; no new database schema was needed for that
  read-only installed receipt. There is no exception bypass today.
- Establish protected-branch/release controls, builder isolation review and
  independent supply-chain assessment. Do not claim a SLSA level from this
  workflow alone.

## Primary references

- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [GitHub CLI verification options](https://cli.github.com/manual/gh_attestation_verify)
- [CycloneDX Go inventory generator](https://github.com/CycloneDX/cyclonedx-gomod)
- [Go vulnerability database](https://go.dev/doc/security/vuln/database)
