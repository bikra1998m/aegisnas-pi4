# Historical reconciliation and roadmap — 2026-10-27

The archive was already streamed and reconciled in the preserved
[original history report](2026-10-15-history-reconciliation.md). It was not loaded
again or used to reverse newer development. The current baseline retains all
130 reports, existing source changes and the unchanged HEAD.

This continuation confirms a remaining trust-boundary requirement: staged
content and policy must be checked again before activation. An admission receipt
is not a fresh signature. The new tool supplies that check but does not turn it
into an activation transaction or authentication for legacy raw restore paths.
The reproduced permission/schema defects were corrected with regression evidence;
previous plans are not treated as proof that those protections already existed.

The roadmap still has **90 recorded Complete, 21 Partial and 24 Missing** features.
No milestone was promoted. [All 135 current rows](2026-10-27-reverification-milestones.csv)
include dependency ordering and remaining work. Complete labels remain historical
engineering assessments, not fresh live acceptance of every completed roadmap.

- NAS-0116 (sequence 4): first unfinished, Partial. Re-verification is implemented;
  activation, actual signing/build/image/security/governance acceptance remains.
- NAS-0008 (sequence 6): next independent unfinished track, Partial. Conversion,
  coordinated PostgreSQL recovery, complete service writes, HA/outage/soak and
  production acceptance are still required.
- NAS-0099 (sequence 16): Missing; depends on NAS-0008.
- NAS-0092..0097: Partial preserved; no configuration/persistence-only or preview
  feature was promoted to verified live telecom enforcement.

Required prerequisites include real candidate/Store/model identities and signing
execution, clean reviewed source and passing security evidence, isolated build
capacity, production policy decisions, Pi boot/firmware hardware and relevant
external device/telecom integrations. There is also unfinished software; the
remaining work is not described as only an infrastructure problem.

No GitHub commit/push was performed: completed milestones and successful required
tests remain the user's publication condition. Current code/test/report changes
are reviewable in the exact change ledger; no reset, force push or deployment
was used to conceal failures.
