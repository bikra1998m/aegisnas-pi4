# Final dependency and OS security assessment

Implementation and the main regression suites were executed on **October 23, 2026**. This report was reconciled on **October 26** without changing tested runtime sources. October 26 evidence is labeled separately; earlier attempts remain preserved. The filename retains the implementation start date.

**Release decision: BLOCKED.** The policy was not relaxed. October 23 strict gate blockers:

- candidate requires a clean committed source tree
- 2 dependency vulnerability findings violate policy

October 23 collector outcomes:

| Collector | Exit | Duration seconds |
|---|---:|---:|
| go-mod-verify | 0 | 727.366 |
| go-sbom | 0 | 175.912 |
| go-vulnerabilities | 0 | 79.757 |
| go-vulnerabilities-arm64 | 0 | 7.877 |
| npm-sbom | 0 | 163.361 |
| npm-vulnerabilities | 0 | 4.340 |

October 23 source/security evidence is in `.tmp/sql-accounting-20261023/security-verified/`; exposure analysis is in `security-verified-exposure/`. A collector exit zero means the scan ran, not that the policy passed. The first attempt timed out module verification and Go SBOM collection under storage pressure; its incomplete/invalid gate finding list must not be described as a vulnerability-free result. It is preserved in `security/`.

The final complete inventory reports 65 Go components and 184 npm components including development/build dependencies, zero npm advisories, and GO-2026-5932 in x/crypto v0.58.0 on both Linux targets; no fixed version is supplied by the advisory. The retained first complete scan predates the final provider/summary corrections; `security-verified/` contains the newly executed collectors against the final code. A module-level finding differs from reachable shipped code; absence of affected OpenPGP imports does not waive this conservative installed-dependency policy, and package-level analysis is not symbol-level exploitability proof.

OS results are **retained earlier October 23 scan evidence**, not a newly executed Trivy run: 1,732 components, 73,964 occurrences / 7,799 IDs overall; 9,380 blocking occurrences (8,980 HIGH, 400 CRITICAL), 964 blocking IDs across 18 installed packages. Trivy 0.76.0 used advisory data dated 2026-10-23T01:18:09.482141619Z. October 23 OS/dpkg identity hashes matched that snapshot in `pre-archive-vm-final-checks.json`. They changed by October 26; see the fresh assessment below. Installed headers/old kernels contribute to counts. These numbers are not a measure of reachable vulnerabilities in shipped runtime code. Snap/container contents, firmware, full signed images and executable drift remain outside that snapshot.

Trusted GitHub signing and a real signed admitted candidate remain NOT TESTED. Production activation and authenticated DB/config rollback are not complete. Read-only GitHub main matched local HEAD; that does not prove signing permissions or production trust. Reports generated after scanning are a later source-state change; a release needs fresh evidence for its exact clean committed source. No signature, ignore list or certification evidence was fabricated.

## October 26 fresh assessment

The first October 26 run timed out Go module verification and Go SBOM collection at 900 seconds each; its incomplete gate and failed exposure analysis remain preserved. Only those two failed collectors were retried. The four successful October 26 collectors were reused after their hashes and identical source snapshot were verified; their original execution records and the earliest evidence timestamp were retained. No successful test was relabeled as newly executed. Retry evidence is in `security-20261026-retry/`, with explicit reuse provenance. All collector details, source binding and gate decisions are recorded under `oct26_revalidation` in the results JSON. Dependency gate: **BLOCKED**; blockers: the source is uncommitted, and the Go finding violates policy on both Linux targets. A zero collector exit means collection ran; it does not mean the conservative release policy passed. All six collector results have exit code zero. The initial incomplete run remains failed; the replacement evidence is complete and includes explicit provenance for the four reused successful collectors. The October 23 inventory remains separately dated.

Final October 26 inventory: **65 Go components, 184 npm components (including development/build dependencies), zero npm advisories**. Both Go targets still report module-only GO-2026-5932 without a fixed version in the advisory. The successful current exposure analysis binds to the same source/dependency snapshot and confirms the affected OpenPGP packages are absent from shipped command imports. Symbol-level exploitability remains **NOT TESTED**; the conservative policy is **not waived**.

The fresh OS scan used Trivy 0.76.0 and advisory data updated at `2026-10-26T07:15:18.945937093Z`, valid until `2026-10-27T07:15:18.945936953Z`. The package inputs stayed unchanged during collection.

| October 26 OS measure | Result |
|---|---:|
| Inventoried components | 1,733 |
| All vulnerability occurrences / unique IDs | 73,985 / 7,805 |
| Blocking occurrences | 9,380 |
| CRITICAL / HIGH blocking occurrences | 400 / 8,980 |
| Unique blocking IDs / affected installed packages | 964 / 18 |

The first refresh hit a 180-second SSH read timeout and remains **FAIL** in `os-20261026/failure.json`; the first replacement failed to persist a Unicode scanner notice under Windows cp1252 (preserved separately), and the UTF-8 replacement scan is separate in `os-20261026-final/`. This fresh inventory covers the changed package database. The October 23 counts above are historical, not silently reused as current. Installed package findings do not prove exploitability in shipped application code, and the inventory still excludes snap/container contents, firmware and executable drift.

Trusted signing, complete candidate inventory, activation/authenticated rollback and exact clean-source binding remain open. No successful vulnerability scan or health probe overrides those gates.
