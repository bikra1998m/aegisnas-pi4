# Development checkpoint and release assessment — 2026-10-29

**Roadmap: 90 Complete / 21 Partial / 24 Missing. NAS-0116: Partial.
Release admission and production activation: BLOCKED.**

This is a development checkpoint, not a completed milestone or a release.
Publication of this partial checkpoint is awaiting clarification because the
earlier instruction conditioned commits on milestone completion. The proposed
checkpoint branch preserves `main` and lets hosted CI validate the accumulated
implementation. It would not deploy, sign a candidate, approve an exception, or
declare all roadmaps complete. No VM restart or production configuration/data
change is part of this continuation.

## Implementation and preserved state

The starting HEAD was `7004511cfbea5f30d53db9b6ac768e059d7cfaf1` with 457
modified/untracked entries (264 modified and 193 untracked), no staged changes,
and 1,405 nonignored files. Every file matched the October 27 baseline before
this continuation. The 142 earlier reports and private raw evidence are preserved.

The accumulated changes include PostgreSQL runtime/migration compatibility,
SQL-backed RADIUS accounting with revision guards, dependency upgrades,
release inventories/admission/re-verification, encrypted SQLite recovery staging,
admin API/UI visibility, snap compiler helper corrections, and their tests and
reports. Earlier reports describe their exact implementation and limitations.

This continuation closes a reproduced malformed-evidence validation gap:
dependency evidence schema version `true` or `1.0`, npm audit version `2.0`,
and Trivy report version `2.0` previously compared equal to valid integer
versions. All are now rejected. Three regression methods cover boolean,
floating-point, string and null versions; four failing subcases from the
pre-fix reproduction are retained. The policy still blocks every Go finding.

CI now runs every browser spec, retains Go/Python/browser/recovery evidence on
failure, and runs unsigned development checks on `codex/roadmap-*` branches.
The signing job still requires a successful manual run on `main`.

Git attributes now preserve report bytes without line-ending conversion. All
142 earlier reports were compared with their baseline hashes in the proposed
Git index as well as on disk. One historical report embeds doubled carriage
returns in captured Windows output; its whitespace warnings are retained rather
than editing sealed evidence. Current implementation files pass the whitespace
check. The ordinary Git index and `main` remain unchanged during preparation.

## Executed evidence and current verification limits

| Scope | Status and evidence |
|---|---|
| Full Windows Go suite, October 27 | PASS: 1,457 test/subtest passes, 5 explicit skips, zero failures; exit 0. The complete JSON log was inspected and unchanged Go sources verified on October 29. |
| Windows Python suite, October 29 | PASS: 91 passes / 17 Linux-only skips out of 108 methods; exit 0. |
| Ubuntu Python suite, October 29 | PASS: 108 passes / zero skips; exit 0 in an isolated directory. Positive signature fixtures remain mocked. |
| Malformed-schema reproductions | FAIL before fix: 3 dependency/npm subcases and 1 OS subcase. These unsuccessful attempts remain evidence. |
| Live deployed VM, October 29 | FAIL overall: 19 PASS / 2 FAIL out of 21. Readiness and system-status GETs timed out after 20 seconds; health, authorization, FreeRADIUS configuration and negative PAP packet checks passed. |
| VM service preservation | PASS: eight service identities unchanged across current checks. This does not assert continuity since earlier days. |
| Fresh vet, builds, UI/browser and hosted CI | NOT TESTED to completion at checkpoint preparation; results will be appended after execution. |
| Fresh PostgreSQL/FreeRADIUS isolated integration | NOT TESTED in this continuation yet. Historical 14/18 migration/runtime and real packet evidence is retained separately. |
| GitHub attestation negative check, October 27 | PASS for rejecting an unsigned fixture via the actual GitHub CLI/API. No successful real signature verification is claimed. |
| Fresh npm inventory and audit | PASS: 184 components including development dependencies; all audit severity counts zero, both commands exit 0. |
| Fresh complete Go/OS scan | NOT TESTED here; older inventory/advisory results are not fresh candidate admission evidence. |

The five Go skips are live PostgreSQL migrations/rollback, live PostgreSQL RADIUS
accounting, live PostgreSQL RADIUS module integration, Linux recovery permissions
and live IANA assignment. These are not counted as passes.

## Security and remaining roadmap gates

The [official Go advisory](https://vuln.go.dev/ID/GO-2026-5932.json) was rechecked
on October 29 and still lists no fixed-version event for the unmaintained
OpenPGP packages in `golang.org/x/crypto`. Earlier package-import analysis found
those packages absent from shipped command imports. That distinguishes a
module dependency finding from observed runtime imports; it is neither a
reachability proof nor a waiver of the conservative gate.

Historical evidence records 65 Go and 184 npm inventory components, zero npm
audit findings, and 9,380 high/critical OS finding occurrences (964 unique IDs
over 18 installed packages). These remain historical scan results, not claims
about a newly built signed image. Complete nested snap/firmware coverage and
fresh image-bound OS evidence remain missing.

NAS-0116 still needs a passing trusted signed workflow and genuine signed/tampered
candidate verification, dependency/OS gate remediation, coordinated production
activation and authenticated database/config rollback at all entry points,
full-image coverage, approved exception/remediation/retention governance, and
security/recovery review. A development commit does not satisfy these gates.

NAS-0116 remains the first unfinished item (sequence 4). NAS-0008 is the next
independent Partial track (sequence 6), with production service integration,
durability/HA/failover/soak and deployment acceptance still required. NAS-0099
depends on NAS-0008. Telecom NAS-0092..0097 remain Partial; no configuration-only
or mocked enforcement result has promoted them.

Historical requirements remain reconciled in
[the archive report](2026-10-15-history-reconciliation.md). The archive was
previously streamed read-only; it was not unnecessarily reread or treated as
authority to reverse later corrections.

Private raw evidence for this continuation is in `.tmp/checkpoint-20261029/`;
the completed Go suite and actual unsigned verification are retained in
`.tmp/checkpoint-20261027/`. Earlier unsuccessful scans, timeouts, Linux permission
reproductions and build attempts remain in their original evidence directories.
