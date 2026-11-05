# NAS-0116 security decision and remaining gaps — 2026-10-27

**Decision: BLOCKED. Engineering status: Partial.**

Fixed, with executed reproductions: newly admitted directories could retain
group-write permission under umask 002; JSON boolean schema versions were
accepted as integer 1. New admissions now set protected directory/receipt modes,
reject non-integer schema versions and revalidate policy path protection.
The staged-release verifier independently checks the signed archive, receipt,
state reservation and full payload instead of trusting an on-disk receipt alone.
Existing directories are never silently repaired or admitted by the new checker.

No actual trusted signature success was produced. GitHub CLI was absent on the
tested Windows/Ubuntu PATHs; its configured subprocess boundary is unit-tested.
Local positive tests mock verification and use synthetic scanner records. Hosted
workflow execution, genuine candidate signatures and signed tamper rejection
remain unverified. No signature, identity, hardware evidence or policy approval
was fabricated, and no ignore/force option was introduced.

The primary Go advisory was rechecked on October 27: it still lists the affected
module range from version zero without a fixed-version event. The retained
module-only finding therefore remains blocking under the unchanged policy.
[Official GO-2026-5932 data](https://vuln.go.dev/ID/GO-2026-5932.json).
The attempted latest-module lookup was unavailable through the web tool; no
latest-version or upgrade claim is made. Prior command-import analysis found
the advisory's OpenPGP packages absent from shipped imports; that was not a
waiver and does not establish symbol reachability/exploitability.

Fresh full dependency/npm/OS scanning was **NOT TESTED** here. Dependency inputs
are unchanged. Prior evidence recorded 65 Go / 184 npm components, zero npm audit
findings and the blocking Go finding. The retained installed-OS scan recorded
1,733 components and 9,380 blocking occurrences (400 Critical, 8,980 High),
964 blocking IDs across 18 packages. These are historical installed-package
findings, not fresh results or a claim that every vulnerability is reachable in
NAS runtime. OS-release/lsb-release/dpkg input hashes still match, but nested
snap/firmware coverage and fresh candidate evidence are not supplied by that match.
See [retained security evidence](2026-10-26-appliance-security.md).

Remaining NAS-0116 requirements: integrate verification with atomic activation,
service quiescence and authenticated DB/config recovery at every restore entry;
validate crash/power-loss rollback; finish image/snap/firmware coverage and actual
builds; execute a passing clean-source trusted workflow; resolve blocking findings
or obtain approved governed policy decisions; complete builder/security/permission
review, remediation/retention governance and hardware recovery qualification.
No saved point-in-time re-verification report authorizes future activation.
