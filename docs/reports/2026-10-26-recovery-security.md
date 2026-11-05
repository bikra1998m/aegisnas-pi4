# Dependency and OS security — 2026-10-26

**Final release-security decision: BLOCKED. No policy exceptions or bypasses.**

Fresh govulncheck v1.9.0 package scans covered `./...` including tests with CGO
disabled on Linux AMD64 and ARM64. Both collector exit codes were zero, but each
reported GO-2026-5932 in `golang.org/x/crypto v0.58.0`; scanner exit zero is not a
passing policy gate. The advisory supplied no fixed version. Final source was
unchanged throughout the scan/import-graph collection. New generated reports
subsequently change the dirty tree; no clean signed candidate was produced.

Fresh shipped-command import graphs classify the advisory's affected OpenPGP
packages as absent on both targets. The finding is module-level. Symbol
reachability and exploitability were NOT TESTED. Package absence is explanatory
evidence, not a policy waiver. The configured conservative policy still blocks.

The earlier complete October 26 inventories remain retained: 65 Go and 184 npm
components, successful module checksum verification and zero npm advisories.
Dependency inputs are unchanged; those inventory/npm collectors were NOT RERUN
for this source-only change. The fresh Go diagnostics are not falsely packaged
as a complete new inventory/attestation bundle. A final clean candidate requires
new, matching complete evidence. The original composite scan/failed collection
attempts remain in `.tmp/sql-accounting-20261023/` and the prior security report.

The retained Trivy 0.76.0 OS scan has 1,733 components, 73,985 advisory occurrences
and 7,805 unique IDs. Its gate blocks 9,380 occurrences (400 critical, 8,980 high),
964 unique blocking IDs across 18 installed packages. Fresh guest hashes match
the scanned dpkg/OS inputs. The OS scanner was NOT RERUN because these inputs
did not change. Installed-package findings do not establish exploitability in
running binaries. Snap contents, firmware, container contents and executable
drift are outside this scan's scope.

The recovery envelope uses the standard Go random-nonce GCM primitive and no new
dependency. It provides local symmetric authentication and confidentiality, not
trusted release signing, FIPS certification or production activation approval.
No trusted signed artifact, hosted signing execution or full-image certification
was fabricated. Remaining prerequisites are a gate-passing reviewed committed
candidate, actual trusted workflow/attestation execution and tamper evidence,
coordinated activation/recovery, image/snap/firmware coverage and approved
operational governance. Physical/customer qualification infrastructure remains
unverified; repository/hosted trust controls have not been certified by this run.

Fresh raw evidence: `.tmp/recovery-security-20261026/go-scans-final/`.
Retained complete inventory/OS evidence is linked from the
[previous security report](2026-10-23-sql-accounting-security.md).
