# Dependency and OS security assessment

**Final decision: BLOCKED. No exceptions, ignore list, synthetic signatures or security-policy relaxation were introduced.**

Current-source gate was executed using the preserved October 23 scanner evidence and current repository state. It blocks on (1) dirty/uncommitted source, (2) source changes since that scan and (3) two target findings for the same Go advisory. Output: `.tmp/admission-guard-20261023/current-source-gate.json`. No scanner was rerun in this Python-only continuation. New release packaging must collect fresh evidence for its exact clean source.

| Prior October 23 scanner evidence, preserved | Result |
|---|---|
| Go checksum verification, Go/npm inventories, both target govulncheck scans, npm audit | All 6 collector processes exited 0; this is not a passing security gate |
| Go inventory | 65 components; GO-2026-5932 on x/crypto v0.58.0, once per Linux AMD64/ARM64 target |
| Reachability distinction | Module finding; affected OpenPGP packages absent from shipped command imports in both prior graphs. Symbol reachability NOT TESTED. No fixed version recorded by that scan. Every Go finding still blocks |
| npm inventory/audit | 184 locked components including development/build dependencies; 0 reported vulnerabilities |
| OS inventory | 1,732 components; 73,964 total occurrences / 7,799 distinct advisory IDs |
| OS blocking findings | 9,380 occurrences: 8,980 HIGH + 400 CRITICAL; 964 distinct IDs across 18 packages |
| OS scanner/advisory data | Trivy 0.76.0; advisory DB updated 2026-10-23T01:18:09.482141619Z |
| Running-kernel package association | 548 distinct IDs associated with matching installed kernel packages in prior analysis; no reachability/exploitability proof |

Installed headers and old kernels contribute to inventory findings; counts are not equivalent to reachable vulnerabilities in shipped binaries. The conservative installed-package gate is retained. Snap/container contents, firmware, full signed images and executable drift are outside the recorded OS-only snapshot. Earlier dpkg/OS hashes matched live state at scan time; this continuation did not re-inventory all OS packages or refresh apt catalogs. The prior zero-upgrade simulation used stale catalogs and is not evidence that fixes are unavailable.

Trusted GitHub signing, a real admitted signed candidate, tampered real-artifact rejection and production activation are NOT TESTED. Read-only GitHub access succeeded and main matched local HEAD; it does not prove attestation permissions or production certification. The current sequence tests mock verification and do not supply cryptographic release evidence.

Persistent state is protected local administrative metadata, not a portable signature, encrypted backup, TPM counter or authorization to roll the whole appliance back. Root/physical disk rollback and authenticated DB/config recovery need separate design and testing. Production activation remains blocked regardless of the passing unit suite.

See [prior detailed security report](2026-10-23-continuation-security.md), [package remediation inventory](2026-10-23-continuation-os-remediation.csv), and [strict release policy](../supply-chain-release-security.md).
