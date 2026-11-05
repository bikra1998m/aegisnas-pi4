# NAS-0116 implementation and continuation report - 2026-10-15

The next unfinished dependency-order milestone, NAS-0116, now has implemented
release admission staging, dual-target dependency gates, OS inventory/scanning,
operator visibility and real API test tooling. It remains **Partial**: this is
not a completed signed production release. Live PostgreSQL testing also exposed
and repaired actual migration/seed defects; broader PostgreSQL compatibility
remains unfinished, so NAS-0008 is reopened as Partial.

## Repository and milestone assessment

Baseline branch `main`, commit `7004511cfbea5f30d53db9b6ac768e059d7cfaf1`.
The initial [repository audit](2026-10-15-continuation.md) inventoried all 1,212
tracked files, README, roadmap, history, test configuration and 28 prior VM
reports. This continuation reviewed implementation and actual results rather
than accepting old completion percentages. Existing unrelated/ignored files and
all preceding continuation changes were preserved. No commit, push, release
publication or replacement of the active VM deployment occurred.

Current ledger: **90 historical Complete, 21
Partial, 24 Missing**, 135 total. Complete is a retained historical
engineering label, not fresh certification. NAS-0092..0097 remain reopened
because config/report/preview work does not establish the named telecom data
planes. The [full updated matrix](2026-10-15-nas0116-milestones.csv) preserves
implementation history and per-item remaining work; the
[remaining-work CSV](2026-10-15-nas0116-remaining-roadmap.csv) is sorted in dependency order.

## Implemented features and modified files

| Area | Implementation and practical effect | Principal files |
|---|---|---|
| Dependency remediation | Go 1.26.9 minimum; updated pgx, crypto/sys/text/sync, chi, XML signature and NTLM dependencies; React Router 7.18.4 and Tailwind 4.3.3 migration; repaired optional lock entries; npm audit reaches zero findings | `go.mod`, `go.sum`, `go.work`, `go.work.sum`, UI package/lock/PostCSS/CSS files, CI and development docs |
| Scan coverage | Actual Linux AMD64 and ARM64 package-and-test vulnerability scans; Go/npm CycloneDX; command exit, time, hashes and whole-source identity; failed/incomplete/stale/tampered evidence blocks | `scripts/release_security.py`, `scripts/test_release_security.py` |
| Candidate workflow | Pinned action/tool versions; read-only PR workflow; trusted-main manual provenance and SBOM attestation; verification and real-artifact tamper-rejection step; source/architecture/release-sequence manifest | `.github/workflows/release-candidate.yml`, `scripts/build-release-candidate.sh` |
| Verified staging | Trusted policy pins repository, commits, platform and downgrade floor; private-copy signature verification; bounded safe extraction; complete checksums; clean/fresh evidence; admission receipt; atomic publication into a new directory | `scripts/admit_release.py`, `scripts/test_admit_release.py` |
| OS evidence | Pinned Trivy command inventories rootfs or OCI OS packages, retains evidence and blocks high/critical/unknown findings or scanner failures; detects image/package-state changes | `scripts/scan_os_release.py`, `scripts/test_scan_os_release.py` |
| Operator visibility | Authorized read-only release-security API, OpenAPI, UI and support bundle show missing/invalid receipt or binary mismatch; explicitly distinguish admission record from fresh signature verification | `internal/adminapi/release_security.go`, route/auth/OpenAPI/support files, `ReleaseSecurity.tsx`, route/sidebar and browser tests |
| Real service harness | New isolated DB/config and generated test credential; validates, migrates, seeds, serves real HTTP/UI, checks support-bundle ZIP and measures 100 requests; cleans up only its own process | `scripts/live_api_smoke.py` |
| PostgreSQL fixes | Quote reserved audit column everywhere it is referenced; portable boolean literals in migration, repair and seed paths; PostgreSQL timestamp ordering; real integration test covers all 101 migrations twice, Seed twice, audit readers and rollback | `internal/db/migrate.go`, `schema.go`, `seed.go`, `audit_history.go`, `postgres_integration_test.go`, audit callers and affected tests |
| Documentation | Trust boundary, staging-versus-activation, downgrade policy, OS evidence, reproduction and outstanding release gates; corrected milestone claims | Supply-chain guide, admission runbook, checklists, backlog, master roadmap, these reports |

The [modified-file manifest](2026-10-15-nas0116-modified-files.csv) records exact
paths, Git state and SHA-256 hashes, including preserved changes from the prior
continuation. The candidate-stage receipt is root-managed local metadata, not
a signature; its API hashes only the current on-disk API binary. The scanner
does not certify snaps, firmware, other service binaries or physical devices.

## Build, functional, integration and performance evidence

The [executed-test report](2026-10-15-nas0116-tests.md) includes every final suite,
both PostgreSQL versions, Windows and Ubuntu real API checks, deployed-service
recovery, FreeRADIUS negative PAP, measured latency/microbenchmarks, earlier
failures and explicit unexecuted checks. [Results JSON](2026-10-15-nas0116-results.json)
contains counts, durations, commands, gate findings, inventory sizes and scope.
The [security report](2026-10-15-nas0116-security.md) separates unique advisory
IDs from package occurrences and links the full blocking-finding CSV. The
[evidence manifest](2026-10-15-nas0116-evidence-manifest.json) hashes retained raw
logs and scan outputs.
The user-authorized graceful VM reboot restored access. The existing deployment
remains at the baseline commit; current binaries were run in an isolated test
directory and are not falsely represented as deployed production code.

## Unresolved issues and next dependency order

1. **NAS-0116 (sequence 4):** resolve the remaining strict Go policy finding,
   execute trusted signing and actual signed-artifact tamper verification, bind
   admission to production activation and authenticated database/config rollback,
   complete snap/firmware and signed image coverage, and implement approved
   exception/SLA/retention governance and independent review. No exception or
   unsigned bypass was introduced to make a failing gate green.
2. **NAS-0008 (sequence 6, reopened):** finish and exercise all runtime PostgreSQL
   queries. For example, `internal/db/nas_clients.go` still compares Boolean
   `enabled` columns to integer `1`, and the PostgreSQL driver only rewrites
   placeholders, selected time expressions and INSERT OR IGNORE. Current passing
   migration/seed/audit tests do not cover that full application plane. Add live
   SQL accounting, TLS, migration rehearsal, backup/restore and outage evidence.
3. **NAS-0099 (sequence 16):** replicated database/consensus implementation and
   multi-node failure tests. A second node and witness/replication topology are
   unavailable; the single VM does not establish HA.
4. **NAS-0112 (sequence 17):** Vault/HSM/TPM/envelope providers and real provider,
   rotation, recovery and fail-closed integration. No provider endpoint or hardware
   credentials were supplied.
5. **NAS-0106 (sequence 20):** bounded cross-service tracing and a collector-backed
   end-to-end trace; dependent monitoring work follows it. Do not jump to numeric
   NAS-0098 while earlier dependency-order items remain open.

Software integration gaps are distinct from external blockers. The remaining
roadmap has not been marked complete because code was planned or because a VM
health endpoint returned 200. External domain/device certification, IANA identity,
production SLO/load/soak, exact firmware scope and signing/release control evidence
remain explicit gates. The repo is ready for review of this implemented slice,
with failures and limitations retained rather than hidden.
