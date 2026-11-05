# Dependency and OS security — October 23

**Final release decision: BLOCKED.** Conservative policy is unchanged. No signature, attestation, waiver or production certification was fabricated.

Fresh gate status: `blocked`. Blocking reasons: `["candidate requires a clean committed source tree", "2 dependency vulnerability findings violate policy"]`. Finding IDs: `["GO-2026-5932"]`. Inventory: **65 Go components / 184 npm components**. npm audit counts: `{"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0}`.

| Collector command | Exit | Seconds |
|---|---:|---:|
| go-mod-verify | 0 | 507.52 |
| go-sbom | 0 | 272.175 |
| go-vulnerabilities | 0 | 43.231 |
| go-vulnerabilities-arm64 | 0 | 3.714 |
| npm-sbom | 0 | 24.834 |
| npm-vulnerabilities | 0 | 2.269 |

Detailed inventories, target scan streams, scanner metadata, package-exposure evidence and hashes remain under `.tmp/production-20261023/security-final/` and `security-final-exposure/`. A successful scanner exit means evidence collection, not absence of vulnerabilities.

Current command-import exposure results:

- amd64: GO-2026-5932 — affected_packages_not_imported; shipped affected imports: 0; symbol reachability: not_tested.
- arm64: GO-2026-5932 — affected_packages_not_imported; shipped affected imports: 0; symbol reachability: not_tested.

The Go policy blocks module-level findings even when affected packages are absent from shipped command imports. Exposure analysis is non-waiving and does not prove symbol/call-path reachability. A reachable-runtime claim must not be inferred from the presence of a module advisory. npm inventory includes development dependencies. The raw gate, not a planned version upgrade, determines the decision.

Fresh installed-OS scan: **1732 inventory components; 9380 blocking occurrences / 964 distinct IDs / 18 packages**, including 8980 HIGH and 400 CRITICAL occurrences. Multiple installed kernel versions and package variants contribute separate occurrences. These are installed-package findings, not proof of exploitation or reachability. Both Trivy collection commands exited zero and installed/copied OS identity plus dpkg status hashes matched before/after.

Trivy 0.76.0; advisory DB updated `2026-10-23T01:18:09.482141619Z`, next update `2026-10-24T01:18:09.482141078Z`. Scope excludes firmware, snap/container contents and executable drift. It is not a signed immutable appliance inventory. No OS upgrade or reboot was performed. See [remediation rows](2026-10-23-continuation-os-remediation.csv).

A read-only `apt-get -s dist-upgrade` returned zero proposed upgrades using the VM's cached catalog, whose latest InRelease timestamp is September 30. No apt update/install/removal was run. This stale-catalog simulation does not establish current remediation availability and does not clear scanner findings. Matching running-kernel package names account for 548 distinct blocking IDs; matching a name is not reachability proof.

The first refreshed OS attempt collected compressed output but FAILED during Windows text-log encoding. The UTF-8 retry is the authoritative successful collection; the prior attempt is retained. An initial dependency-wrapper launch failed on an embedded BOM before any scanner ran; the corrected wrapper is reported separately. Reports are finalized after scanning, so candidate admission still requires a fresh scan on the eventual clean approved commit.
