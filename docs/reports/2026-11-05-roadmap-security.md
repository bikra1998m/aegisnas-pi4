# NAS-0116 dependency, OS and admission assessment - 2026-11-05

**Overall release gate: BLOCKED. NAS-0116: Partial.**

The [official Go advisory](https://vuln.go.dev/ID/GO-2026-5932.json), modified
November 2, now defines a fixed parent-module version. The upstream commit
`2f1f834330b2` adds `openpgp/go.mod`, separating deprecated OpenPGP into its own
module. The parent dependency is pinned to
`golang.org/x/crypto v0.58.1-0.20261009181718-2f1f834330b2`.
This does not repair deprecated OpenPGP itself or create a security waiver.
OpenPGP is absent from the downloaded parent and both current module graphs.
The retained upstream compare shows one commit and one added file.

PASS: module checksums, complete 65-component Go inventory, and both Linux AMD64
and ARM64 package vulnerability scans including tests. Both report zero findings
and zero scan errors with govulncheck 1.9.0 / Go 1.26.10. Earlier module-level
OpenPGP findings are historical installed-module exposure, not proof of reachable
runtime code. Current zero findings also do not prove universal absence of flaws.

FAIL/BLOCKED retained: the first complete dependency collection found a new high
`follow-redirects` advisory, [GHSA-mrwp-f3q8-3g9p](https://github.com/advisories/GHSA-mrwp-f3q8-3g9p).
Only that lockfile dependency changed from 1.16.1 to 1.16.2. Fresh inventory and
audit commands both exit zero: 184 npm components including development tools,
zero findings at every severity. The original `security/gate.json` remains blocked.
These newer component results are not substituted into that earlier evidence bundle.
A full clean committed-source gate remains required in hosted CI.

Historical OS scan: 1,733 components; 73,985 occurrences / 7,805 unique IDs;
9,380 high/critical occurrences (8,980 high, 400 critical), 964 blocking IDs across
18 installed packages. Its advisory database was updated October 26. These are
installed-package findings, not proven runtime exploitability or a fresh full-image
assessment. November 5 read-only checks confirm Ubuntu 22.04.5 x86_64,
kernel 6.8.0-138-generic and identical hashes for the three retained OS/dpkg inputs.
Fresh OS scanning is NOT TESTED; unchanged files do not refresh advisory coverage.
Nested snap packages, firmware advisories and signed image binding remain incomplete.

PASS engineering evidence: admission, durable sequence/version protection, staged
payload and current-policy re-verification, strict integer evidence schemas,
protected publication directories, encrypted SQLite recovery staging, API/UI and
support-bundle visibility have dated tests. Positive signature unit fixtures are
mocks. The retained October 27 real unsigned verification failed with HTTP 404;
it is negative evidence, not a successful trusted signature.

BLOCKED: a passing eligible manual-main signing/admission/tamper workflow; atomic
production activation with authenticated database/config rollback at every legacy
entry point; complete image/OS remediation and Store/model identities; supported
Ubuntu Core RADIUS confinement; approved exception/SLA/retention governance;
builder/permissions review and recovery/power-loss drills. GitHub access exists,
so signing is not described as an unavailable account. The development branch
deliberately cannot sign or deploy. Security policy still blocks every Go finding
and high/critical npm/OS findings; no threshold was relaxed.
