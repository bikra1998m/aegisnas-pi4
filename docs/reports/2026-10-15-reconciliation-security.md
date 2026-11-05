# Final dependency and OS security evidence — reconciliation

**Release gate: BLOCKED.** Inventory/scan execution success and vulnerability-policy success are separate outcomes.

## Application dependencies

The complete earlier collector at `.tmp/nas0116-20261015/security-complete/` has six successful commands: module verification, Go and npm CycloneDX inventories, Linux AMD64 and ARM64 Go package/test scans, and npm audit. Its raw evidence hashes were rechecked in this continuation. All six dependency input files are unchanged from that scan. It contains 65 Go and 184 npm component records; the npm inventory includes development dependencies and the audit reports zero vulnerabilities.

Go reports two finding records for **one advisory**, GO-2026-5932, one per target. They identify `golang.org/x/crypto v0.58.0` at module scope, with no affected package or symbol in the scanner trace. The saved advisory identifies seven `golang.org/x/crypto/openpgp` package paths.

The newly executed import analysis collected **413 package imports for AMD64 and 412 for ARM64**, covering `./cmd/...` without tests and with CGO disabled. None of those seven affected package paths is in either graph. Thus this captured advisory is present in the dependency inventory but its listed affected packages are not imported by these shipped command targets. This does **not** establish symbol reachability, exploitability, dynamic plugin safety, other build-tag safety or signed-binary identity. Those claims are **NOT TESTED**.

The policy still blocks every Go finding. No suppression, replacement advisory, invented signature or policy exception was introduced. Analysis exit zero means “analysis completed,” not “release approved.” Raw graphs and a hash-bound report are in `.tmp/reconcile-20261015/go-exposure/`.

The working source has changed since the original scan, including these runtime fixes and reports. The final candidate therefore also fails clean-source/source-match requirements. Retaining a valid earlier dependency snapshot is not permission to sign this new working tree; a fresh collector run on reviewed committed candidate source is required.

## VM OS evidence and exposure limits

The read-only VM probe confirmed the same deployed commit, running kernel `6.8.0-138-generic`, `/etc/os-release` SHA-256 `594d5ddd35aedb47f00d9c34d140017907a5b9f93c975aba125fc924daac5c07` and dpkg status SHA-256 `fcacb7e871a0fc3504c8f7a56aa53f92fb9ddbcaa3cf820f652065e97e848e03` as the completed Trivy 0.76.0 scan. No redundant rootfs scan was run.

| Captured OS result | Count |
|---|---:|
| Package inventory records | 1,731 |
| Package/advisory occurrences, all severities | 69,921 |
| Unique advisories, all severities | 7,460 |
| High occurrences | 4,062 |
| Critical occurrences | 174 |
| Blocking occurrences | 4,236 |
| Unique blocking advisories | 537 |
| Packages with blocking findings | 18 |
| Blocking occurrences with a listed fix | 1,508 |

Repeated kernel/header/tool packages account for many occurrences. These are not 4,236 independently reachable network exploits. However, packages associated with the running kernel have 193 unique blocking advisory IDs / 1,158 occurrences, so obsolete-package removal alone cannot establish a clean gate. The captured scanner did not provide a fixed version for that running-kernel subset. No unreviewed package removal, kernel upgrade or reboot occurred.

The full previous [OS finding ledger](2026-10-15-nas0116-os-blocking-findings.csv) and raw scan remain unchanged. Ubuntu vendor applicability review, a maintenance/recovery plan and a fresh scan of the intended image remain required. Snap contents, firmware, production images and hardware exploitability are **NOT TESTED**. The lab's Ubuntu 22.04 result does not certify Ubuntu 24.04 or Ubuntu Core 24.

## Signing and failures retained

Actual trusted signing and actual signed-artifact negative tests are **BLOCKED** by the absence of a trusted signed candidate and connected verifier infrastructure. Local admission fixtures and workflow syntax checks pass only their stated scope.

Earlier incomplete scanner attempts remain under `security-evidence/` and `security-final/`: optional npm inventory failure, source drift and unavailable tool PATH were resolved before the complete collector. They have not been erased or counted as passing scans. New PostgreSQL failure evidence is separate in the [integration report](2026-10-15-reconciliation-postgresql.md).

See [NAS-0116 remaining work](2026-10-15-reconciliation-nas0116.md) and the [release assessment](2026-10-15-reconciliation-readiness.md).
