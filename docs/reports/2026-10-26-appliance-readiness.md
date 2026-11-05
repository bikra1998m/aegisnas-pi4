# Appliance continuation readiness — 2026-10-26

**Release gate: BLOCKED. NAS-0116 remains Partial; no milestone was newly completed.**
The roadmap still records 90 Complete, 21 Partial and 24 Missing features. Complete
labels are historical engineering classifications, not fresh production certification.

This continuation implements bounded snap-blob/firmware/boot file inventories,
independent-digest comparison, safe partial reports on cancellation/time limits,
and repairs the lab snap build paths and exact Go compiler selection.

| Latest executed validation | Result |
|---|---|
| Windows Python regression | PASS: 66 passed, 13 explicit platform skips; 79 methods |
| Ubuntu Python regression | PASS: 79 passed, no skips |
| YAML parsing | PASS: 8 snap recipes and 2 workflows, PyYAML 5.4.1 |
| Real deployed service/API/RADIUS smoke retry | PASS: 21/21 |
| Earlier deployed smoke batch | FAIL: 16/21; five HTTP timeouts retained |
| Service continuity | FAIL: FreeRADIUS watchdog/startup failures and automatic restarts |
| Complete real snap/firmware/boot inventory | BLOCKED: incomplete; bounded run retained partial evidence |
| Actual Snapcraft packages / signed Core image | BLOCKED: not built or certified |

The new build helper's actual compile results are in the [test report](2026-10-26-appliance-tests.md).
They must not be confused with full Snapcraft packaging or release admission.
The first actual compile timed out. Unit build contracts use test doubles.

The VM recovered sufficiently for all 21 smoke checks to pass, but its API still
returns `ready:false` with five production blockers. Security also retains the
Go module finding and installed-OS high/critical findings. No waiver, signature,
production activation, database restore, manual service restart or reboot was performed.

HEAD remains `7004511cfbea5f30d53db9b6ac768e059d7cfaf1`. No files are staged and no commit or push was made:
the requested completed-milestone/successful-required-testing condition is not met.
Exact Git status and counts are in [source state](2026-10-26-appliance-source-state.json).
All 114 prior reports are preserved byte-for-byte.

Reports: [implementation](2026-10-26-appliance-implementation.md), [tests](2026-10-26-appliance-tests.md),
[Windows](2026-10-26-appliance-windows.md), [Ubuntu](2026-10-26-appliance-ubuntu.md),
[PostgreSQL scope](2026-10-26-appliance-postgresql.md), [NAS-0116 gaps](2026-10-26-appliance-nas0116.md),
[live services](2026-10-26-appliance-live-services.md), [security](2026-10-26-appliance-security.md),
[history and roadmap](2026-10-26-appliance-history-roadmap.md), [22 exact changes](2026-10-26-appliance-changes.csv),
[all 135 milestones](2026-10-26-appliance-milestones.csv), [machine-readable results](2026-10-26-appliance-results.json),
[raw evidence hashes](2026-10-26-appliance-evidence-manifest.json).

Next: finish NAS-0116 activation/recovery integration and full-image coverage,
resolve security and operational blockers, and run a trusted passing workflow.
NAS-0008 remains the next independent unfinished data-plane track; NAS-0099
depends on it. Hardware telecom milestones remain Partial.
