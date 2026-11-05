# AegisNAS continuation audit and execution report — 2026-10-15

This report separates implemented software, recorded milestone claims, tests
executed during this continuation, and external certification. It is not a
production approval. Times use Asia/Colombo; raw tool timestamps may also use UTC.

## Repository and evidence reviewed

Baseline: `main`, commit `7004511cfbea5f30d53db9b6ac768e059d7cfaf1`. The tracked
working tree was clean at entry. Existing ignored binaries, `.tmp` artifacts,
VM scripts and prior reports were preserved. No commit, push, deployment or
publication was performed.

The inventory scanned all 1,212 tracked files, including 219 documentation
files and 417 Go/browser test files. It covers the 16 command files, 827 internal
files, 49 config assets, 53 web files, deployment/image/snap assets, CI, Makefile,
module/workspace/lockfiles, all 135 backlog rows and dependency sequence, vendor
roadmap, implementation commits, and 28 historical VM report files. Deep review
focused on the next unfinished dependency, recent telecom implementations,
database migrations, configuration loading, test harnesses and observed failures.
This inventory and targeted review do not constitute a line-by-line security
audit of every generated registry entry or every implementation.

Reproducible local artifacts are under `.tmp/continuation-20261015/`, including
`repository-inventory.json`, raw test/scanner logs, the isolated live-service
probe, `audit-summary.json` and tool installation logs. Those local artifacts
are ignored by Git. The durable summaries are
[results JSON](2026-10-15-results.json) and
[the complete milestone matrix](2026-10-15-milestones.csv).

## Milestone assessment

| Assessment | At entry | After audit |
|---|---:|---:|
| Recorded Complete | 97 | 91 |
| Partial | 14 | 20 |
| Missing / pending | 24 | 24 |
| Total | 135 | 135 |

The 91 retained Complete labels (NAS-0001..0091) have implementation history,
software artifacts and tests; they are **historical engineering labels**, not
a fresh certification that every definition-of-done gate passed. External
release checklists remain open. In particular, the new PostgreSQL test cannot
establish NAS-0008 live compatibility without a database, and this run does not
establish real hardware enforcement for vendor or wireless features.

NAS-0092..0097 are reopened as **Partial**, not Missing: the configuration,
preview, profile/event persistence, API/UI and test work exists. Their named
`Apply*` functions in `internal/enforcement/mobile_*.go` chiefly generate
reports and write evidence/runtime status. No integration from those named
lifecycles into the RADIUS packet path was found that establishes live mobile
session/bearer, charging, policy control, WiMAX or DOCSIS behavior. Shared
typed VSA and generic accounting primitives are useful prerequisites, not proof
of those complete domain workflows.

The latest historical NAS-0097 VM report explicitly records `status: disabled`,
one skipped apply and zero applied events, yet prints 100% completion. That
report demonstrates API/configuration availability; it does not demonstrate
CMTS provisioning, service-flow enforcement or IPDR mediation. The current
runtime still contains hardcoded completion/readiness claims for these slices;
removing those misleading API claims and implementing the actual data plane
remain tracked software work. Documentation and the authoritative backlog now
state the narrower evidence accurately.

The executable order is the sequence CSV, not ascending feature number.
NAS-0116 is the earliest unfinished item (sequence 4, dependency NAS-0001),
followed by NAS-0099, NAS-0112 and NAS-0106. Advancing directly to NAS-0098 would
skip those items. This continuation implements a concrete NAS-0116 slice and
repairs demonstrated regressions; it does not close that work package.

## Implemented changes

| Area | Change and practical effect |
|---|---|
| NAS-0116 evidence | New Python CLI captures Go/npm CycloneDX inventories, module checksum verification, vulnerability findings, command status/duration, stderr hashes and source/dependency fingerprints. It rejects missing, failed, malformed, tampered, stale or source-mismatched evidence. |
| Candidate gate | Every Go module-level finding and npm high/critical finding blocks. No silent scanner-failure pass, unsigned fallback or ignore-list was added. |
| Signing workflow | New pinned-action CI workflow tests and builds Linux AMD64/ARM64 candidates. A manual `main` run can attest provenance and SBOMs, then verify repository, workflow, commit, branch and hosted-runner identity before uploading a verified candidate. It does not publish or deploy. |
| Security tests | Negative tests exercise scanner failures, zero-exit JSON findings, inventory completeness, evidence integrity, freshness, source mismatch and verifier failure. Cryptographic verification is delegated to GitHub CLI, not replaced with a checksum. |
| Quick Start | Fixed numeric Passpoint OSU method configuration, unresolved address/route/translation references, wholesale proxy route references and commercial plan references. Aligned shared pool CIDRs and the reservation. The actual checked-in example now loads and validates. |
| Config regression | Added a test for the complete checked-in example, including matching network ranges for pools shared between RADIUS policy and broadband leases. |
| PostgreSQL prerequisite | Added an opt-in live migration/idempotency/transaction-rollback test using a unique schema in a supplied disposable database. Cleanup is restricted to that generated schema. |
| Frontend dependencies | Applied compatible lockfile updates using `npm audit fix --ignore-scripts`; advisories fell from 17 (12 high) to 9 (5 high). No forced major framework migration was applied. |
| Claim correction | Reopened six telecom milestones; corrected stale roadmap distribution wording; qualified README production claims; added milestone and release-security reports/checklists. |

## Executed validation

Final machine-readable counts, durations and failures are in
[2026-10-15-results.json](2026-10-15-results.json). Raw command outputs remain in
the local artifact directory. A command emitting `PASS` while skipping an
integration test is not counted as live integration success.

| Check | Result / scope |
|---|---|
| `go build ./...` | Failed: host memory allocation failure in Go runtime during concurrent builds. |
| `GOMAXPROCS=2 go build -p=1 ./...` | Passed; 399.17 seconds. |
| Linux ARM64 cross-build | Passed with `CGO_ENABLED=0`, `GOMAXPROCS=2`, `-p=1`; 436.02 seconds. This is compile evidence, not execution on a Pi. |
| Full uncached Go suite | Failed overall (exit 1), 2,594.47 seconds: 1,386 passing test/subtest results, 2 failures, 1 live-IANA skip; 39 packages passed, 1 failed, 12 had no tests. |
| Isolated session reruns | Both failed cases passed 3 repetitions each (6/6), 137.86 seconds. Original full-suite failure remains recorded. |
| `go vet -p=1 ./...` | Passed. |
| Config package and acceptance rerun | Passed after example fixes. Acceptance package uses local SQLite/software fixtures, not an external LDAP/FreeRADIUS lab. |
| `npm ci`, original UI build | Executed successfully; original minified JS was 1,521.82 kB, gzip 242.36 kB. |
| UI build after compatible updates | Passed; minified JS 1,535.06 kB, gzip 246.47 kB. Existing >500 kB chunk warning remains. |
| Browser baseline | 27 passed, 8 timed out; several timed out during browser page setup under concurrent load. |
| Browser rerun after updates | All 35 passed, zero skips/retries, one worker and 60-second test timeout; 111.14 seconds total. Browser tests use mocked API responses and do not replace backend/device integration. |
| Release-security unit suite | 14 tests passed, including negative paths. Mocked verifier tests do not count as a real signed-artifact verification. |
| PostgreSQL live test | Skipped explicitly: `AEGIS_TEST_POSTGRES_DSN` absent. Compilation/skip path executed; no PostgreSQL success claimed. |
| Existing registry fuzz target | Passed a 15-second run with one worker: 47,542 executions, 16 new interesting inputs, no reported crash. This is not a complete malformed-packet corpus or long fuzz campaign. |
| Shell syntax | `bash -n scripts/build-release-candidate.sh` executed successfully. |
| Workflow syntax | Parsed with the repository's Go YAML library; 2 jobs and all action references pinned to full SHAs. This does not execute GitHub Actions. |
| Dependency scans | npm audit and Go module vulnerability scan executed. Findings remain blocking; details below. |

The real collector completed all five commands: module verification (exit 0,
782.53 s), Go SBOM (exit 0, 109.62 s, 65 components), npm SBOM (exit 0, 5.36 s,
199 components), Go vulnerability scan (exit 0, 1.91 s, findings present), and
npm audit (exit 1, 4.34 s, findings present). The gate correctly blocked on 67
Go/npm findings and on source edits made while the scan ran. Dependency files
were unchanged during that collection, but the entire source snapshot was not
stable; these artifacts cannot authorize a candidate. A new scan of the final
committed tree is required before any release. The collector's Go module scan
was corrected during implementation to run without package patterns from a
package directory; its initial invocation errors were not treated as scans.

### Real local HTTP service

A newly built admin CLI/API used a temporary database/configuration and generated
test-only bearer token. Executed: full config validation, schema migration,
seeding, process startup, public health (200), unauthenticated roles rejection
(401), authenticated database/roles/DOCSIS status (200), bodyless DOCSIS preview
(200), and UI serving (200). The process was stopped after the check. This is
fresh real HTTP/SQLite evidence, not a mocked handler test.

An earlier probe sending `{}` to the bodyless preview endpoint saw a Windows
connection reset while the server log recorded HTTP 200. A repeat with the
documented empty-body request succeeded. The reset was not established as a
fixed product defect; both outcomes are retained in local evidence.

### Measured performance

Windows AMD64, Intel Core i5-11400, `GOMAXPROCS=2`, existing Go benchmarks:

| Benchmark | Result | Allocation |
|---|---:|---:|
| Typed registry wire lookup | 250.6 ns/op | 400 B/op, 3 allocs/op |
| IANA assignment lookup | 8,897 ns/op | 66,374 B/op, 28 allocs/op |

These are single-host microbenchmarks during development load. They do not
measure Raspberry Pi capacity, RADIUS requests per second, concurrent sessions,
p95/p99 network latency, failover RPO/RTO or production soak behavior. HTTP probe
durations are in results JSON; their single samples are not latency SLOs.

## Failures and unresolved software work

- The fresh Go module scan found 62 findings across 57 unique vulnerability IDs:
  standard library 39, `golang.org/x/crypto` 17, pgx 3, `x/text` 2, `x/sys` 1.
  These are **module-level** findings, not proof that every vulnerable symbol
  is reachable. Exact IDs, affected versions and suggested fixes are retained
  in results JSON. A Go toolchain/dependency upgrade and regression run remain.
- npm still reports five high and four moderate findings. The remaining high
  chain involves braces/chokidar/micromatch/fast-glob/Tailwind 3; suggested fixes
  require a Tailwind major upgrade. React Router findings also require reviewed
  major-version remediation. The candidate gate intentionally stays blocked.
- NAS-0116 still needs actual trusted-workflow execution, real signature and
  tampering evidence, installer/update/rollback signature admission, OS/image
  inventories, governed exception/remediation policy, and API/UI audit state.
- The full suite exposed session termination/accounting timing failures; see
  final run disposition below. No test expectation was weakened to hide them.
- The acceptance harness silently falls back to a reduced configuration when
  loading the example fails. The new direct example regression test prevents
  the demonstrated Quick Start failure from being hidden by that fallback;
  restructuring acceptance fixtures remains useful follow-up work.
- Production identity, exact vendor firmware behavior and telemetry claims
  still need their separate evidence. A successful disabled-feature preview
  must not be promoted to a complete enforcement claim.

## Infrastructure and credential blockers

| Requirement | Observed availability and limit |
|---|---|
| Previous Ubuntu VM | `192.168.50.1` reached SSH, but existing noninteractive authentication failed (`Permission denied`). No `AEGIS_VM_PASSWORD` supplied. No services changed and no prior VM success re-used as a fresh pass. |
| Docker Linux services | Docker CLI exists; the Docker Desktop Linux engine pipe is absent. No accessible daemon for PostgreSQL/FreeRADIUS containers. |
| WSL Ubuntu | Distribution exists, but systemd session/bus initialization reported errors; PostgreSQL, Go and FreeRADIUS binaries were not available in the inspected paths. |
| Production PostgreSQL/consensus | No test DSN or running PostgreSQL cluster was provided. Replication, quorum, partitions, fencing, synchronous state and failover tests remain unexecuted. |
| Signing | GitHub Actions OIDC/attestation credentials exist only in a trusted workflow run; no workflow was pushed or dispatched. Local mock tests are not signing evidence. |
| Hardware/domain labs | No Pi4, AP/CMTS/modem, BNG/LAC/LNS, carrier packet core, SIM vector service, Vault/HSM/TPM or partner billing/controller credentials were accessible. |
| Long-duration proof | 30-day soak, customer acceptance, independent security audit and compliance certification were not executed. |

## Remaining roadmap in dependency order

The [135-row matrix](2026-10-15-milestones.csv) records every feature, its original
and revised status, dependencies, implementation commit/file pointers and
remaining work. The authoritative sequence was not reordered.

1. Finish NAS-0116 software work and dependency remediation; obtain a real
   signed candidate and admission evidence.
2. NAS-0099 replicated database/consensus, NAS-0112 Vault/HSM/TPM/envelope
   encryption, and NAS-0106 tracing are the next earlier unfinished packages.
   Architecture and code are still required; credentials alone do not finish them.
3. Reopened NAS-0092 is a prerequisite for the remaining mobile work. NAS-0121
   golden vectors and NAS-0122 comprehensive malformed/property/fuzz coverage
   remain incomplete; one short existing fuzz run does not complete them.
4. Complete remaining HA, monitoring, security, voice/VPN, lab and release
   governance packages as listed in the matrix. NAS-0098 is still Missing.
5. Execute hardware, interoperability, scale, partition, rollback and soak gates
   against each exact supported release and firmware combination.

The remaining multi-month engineering packages have not been implemented by
this continuation. They remain open explicitly, rather than being marked done
from plans, scaffolding or unavailable test evidence.

## Modified files

- `.github/workflows/release-candidate.yml`: candidate security/test/signing jobs.
- `scripts/release_security.py`, `scripts/test_release_security.py`,
  `scripts/build-release-candidate.sh`: evidence gate, negative tests and packaging.
- `configs/config.example.yaml`, `internal/config/config_test.go`: working
  Quick Start example and full-example regression coverage.
- `internal/db/postgres_integration_test.go`: opt-in isolated-schema live test.
- `web/admin-ui/package-lock.json`: compatible dependency remediation.
- `.gitignore`: Python tooling caches.
- `README.md`, `docs/development.md`: readiness qualification and test guidance.
- `docs/enterprise-nas-engineering-backlog.csv`, master roadmap, and
  `docs/nas-0092..0097-release-certification-checklist.md`: corrected milestone claims.
- `docs/supply-chain-release-security.md`, NAS-0116 checklist and this report's
  CSV/JSON companions: implementation scope, evidence and remaining work.

## Final run disposition

The full Go suite failed only in `internal/sessions`:
`TestManager_ReclassifyByCriteriaImmediateIdleTimeout` did not observe the
expected stopped state within its assertion deadline, and
`TestManager_ReclassifyByCriteriaVLANChangeRequiresReauth` exceeded the cleanup
deadline while awaiting asynchronous accounting. Both passed all three isolated
repetitions without code changes or relaxed assertions. Resource contention is
a plausible cause; it was not proven. No session-runtime fix is claimed, and a
fresh full-suite pass on an adequately provisioned runner remains a release gate.

Windows and Linux ARM64 builds, vet, updated config/acceptance tests, the 35-test
browser run, 14 new security tests, the short fuzz campaign, microbenchmarks and
local HTTP smoke check completed as recorded above. PostgreSQL and live IANA
were skipped for missing inputs. The supply-chain gate remains blocked by real
dependency findings and the changing development snapshot. Signed candidate
execution and the external deployment/device tests remain unexecuted.
