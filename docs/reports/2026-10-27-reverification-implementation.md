# Current implementation audit — 2026-10-27

Baseline `2026-10-27T07:14:02.404612+00:00`: HEAD `7004511cfbea5f30d53db9b6ac768e059d7cfaf1`, 442 unstaged Git entries,
1,390 repository files and 130 existing reports. This slice changes 12 files
([before/after hashes](2026-10-27-reverification-changes.csv)); all unrelated baseline content is preserved.

## Implemented behavior

- `admit_release.py`: bounded, stable private copies reject candidate symlinks,
  hard links and special files; input identity/size changes fail. Extracted
  directories are explicitly 0755 and receipts 0644 before publication,
  independent of a group-writable umask. Current policy trust/contents are
  revalidated at the end. Schema versions require integer 1, not boolean true.
- `reverify_release.py`: holds the existing sequence lock, binds the original
  artifact/receipt/current reservation, repeats both GitHub predicate checks,
  extracts/validates fresh evidence through the real security engine, and checks
  every staged file/directory and Linux modes. It rejects forged receipts,
  changed/missing/extra files, unsafe paths, stale/failing evidence, downgraded
  reservations and concurrent policy/state/tree changes. It does not rewrite
  receipt/state or silently fix existing permissions. The returned point-in-time
  result explicitly does not authorize production activation.
- `release_security.py`: GitHub verifier stdout goes to stderr, retaining
  diagnostics while preserving structured CLI stdout. No policy waiver or
  verification identity constraint was removed.
- Tests exercise real filesystem behavior and real evidence-policy logic with
  synthetic scanner records. Local positive signature checks are mocked.
- Release CI re-verifies both admitted candidates before verified upload and
  retains admission/re-verification evidence separately on failed runs. YAML
  parsing passed; a real hosted execution is NOT TESTED.
- Operator/development/checklist/roadmap documentation and the NAS-0116 backlog
  row explain scope, current-policy behavior and remaining requirements.

## Acceptance boundaries

This completes a re-verification prerequisite, not an activation transaction.
It does not cover atomic DB/config/binary switching, service quiescence,
rollback after power loss, OS/firmware compatibility or every legacy restore
entry point. A saved JSON result cannot authorize a later operation after content
changes. Administrative ownership and immutable handling remain trust assumptions.
Large artifacts, maximum bounds, concurrent throughput and physical power loss
are NOT TESTED. The [operator guide](../release-reverification.md) records the
2 GiB archive / 4 GiB expanded / 10,000-entry / 4 MiB receipt limits and resource scope.

No Go, UI, dependency-lock or database-schema source changed. The relevant
959 source/dependency hashes remain equal to this turn's baseline.
Existing working functionality, VM configuration and older reports were retained.
No production deployment, database restore, package upgrade, service restart or
VM reboot was issued. The process-list observation initially missed VMware;
the management tool confirmed one running VM. About 2 GB free host RAM was
observed, so prior heavy compilation/inventory failures were not blindly repeated.
