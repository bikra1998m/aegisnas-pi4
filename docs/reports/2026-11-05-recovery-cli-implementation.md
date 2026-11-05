# Recovery implementation and historical reconciliation — 2026-11-05

The starting root HEAD was `7004511cfbea5f30d53db9b6ac768e059d7cfaf1` on `main`, with 476 existing
Git status entries and no staged changes. The already-published development branch
was `9880861098fbdc172c21075724b09aa88310e2e7`. The 1,423 nonignored source files matched the
previous reviewed snapshot exactly. All 159 prior reports remain byte-identical.
The working root was not reset and no historical evidence was deleted.

The original archive was already streamed read-only in the prior reconciliation:
560,372,183 bytes, 169,946 records, zero parse errors. Its requirements remain in
[the historical reconciliation](2026-10-15-history-reconciliation.md); there was no
reason to load or reinterpret the entire archive again. This repair directly
addresses its preservation, recovery validation and no-unverified-completion rules.
The old description of the CLI output as a full appliance archive was inaccurate:
it contains SQLite, optional configuration and a checksum manifest only. The
operator guide now makes that scope and authentication limitation explicit.

Implemented behavior:

- Use read-only SQLite `VACUUM INTO` for a consistent snapshot including committed
  WAL transactions; verify integrity and include the config actually loaded.
- Reject PostgreSQL and missing/nonregular databases before output or connections.
  Never overwrite an existing backup; create private Linux files and propagate I/O errors.
- Bound compressed/expanded input; allow only the historical flat payload names;
  reject duplicates, links, specials, corrupt/truncated trailers and hidden streams.
- Require strict JSON manifest keys, complete file coverage and valid SHA-256 values.
  Validate database, candidate config, same database path and destinations before confirmation.
- Refuse SQLite sidecars, aliased targets and linked paths. Stage every replacement
  and safety copy before the first rename; compensate ordinary later I/O failures.
- Keep the existing encrypted recovery path separate; add actual command fixtures
  to normal CI and release-security workflows, retaining stdout/stderr/result evidence.

Tests reproduced six defect categories (nine invalid cases; eleven failed test/subtest
events including parent aggregation) before the fix. The first implementation run
also failed on a Windows SQLite URI authority; `/C:/` URI handling was corrected
and paths with spaces/special characters were covered. Both unsuccessful attempts
are retained. The passing result is not substituted into their logs.

Limits: local checksums do not authenticate an archive. Separate DB/config snapshots
are not a cross-service transaction. The operator must stop all clients; absent
sidecars are insufficient proof. Compensation does not guarantee power-loss recovery.
Replacement files belong to the invoking account; parent directories must be under
operator control, and Windows ACLs are not certified. Other raw ZIP/API/Ubuntu restore
paths and production activation remain unfinished. No threshold, signature policy,
roadmap classification or device-support claim was weakened.

The specific source/docs/workflow delta is in
[the changes ledger](2026-11-05-recovery-cli-changes.csv). Publication uses the existing
isolated development worktree so the user's original root state stays intact.
