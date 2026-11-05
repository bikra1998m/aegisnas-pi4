# Conversion implementation and historical reconciliation — 2026-11-05

Continuation began from the verified published recovery checkpoint. All 1,437
nonignored files matched the prior reviewed snapshot, including 169 report files.
The original archive's streaming reconciliation remains applicable: see
[historical requirements](2026-10-15-history-reconciliation.md). No old instruction
was used to reverse later improvements or to claim planned work was implemented.

The new conversion path closes an explicitly missing rehearsal capability in
NAS-0008. It uses the existing migration, PostgreSQL dialect, connection-policy and
secret-provider implementations, without changing their global runtime state or
the deployed configuration. New files separate orchestration/snapshotting, table
verification/transaction import, strict value normalization, tests and the CLI.
The Python actual-command fixture is included in both PostgreSQL CI versions.

Validation includes populated schema 1 migrated privately to schema 103; current
schema 103; committed WAL rows; quoted/spaced source paths; all 181 tables; signed
64-bit values; NULL and Boolean handling; UTC timestamps; primary-key order and
canonical content hashes; deleted-ID high-water preservation; enforced foreign keys;
new-schema privacy; existing-schema refusal; failed row-transaction rollback; unknown
tables; invalid/future source versions; cancellation before work; redacted resolver
errors; and explicitly authorized numeric/timestamp precision normalization.

The source is never upgraded in place. A new PostgreSQL schema is reserved with an
advisory lock and PUBLIC schema access is revoked. Import uses one row transaction,
deferred/then-validated foreign keys, restored constraint modes and transactional
sequence restarts. Migration DDL is separate: a failed private schema is retained
for operator inspection, not automatically dropped or activated. A COMMIT connection
failure may have an uncertain outcome and requires inspection. Source writes after
the snapshot are not synchronized. Custom source schema rules and every historical
release variant are not certified. These limits are explicit in the operator guide.

The real Ubuntu test exposed a cold-storage cost that Windows did not: TRUNCATE of
every fresh table/index exceeded the configured statement timeout. Replacing it
with deletion of the few bootstrap rows preserved transaction semantics while
avoiding relation rewrites. The production timeout and durability settings were
not weakened. Both unsuccessful and corrected results are preserved.

Local evidence lives under `.tmp/conversion-20261105/`: `attempt1`, `attempt2`,
`cli-windows`, `cli-windows-retry`, `ubuntu`, and `ubuntu-retry`. Actual fixture
databases/configurations are private and excluded from publication. The failed
Ubuntu test cluster was stopped by its fixture; both before/after service identity
checks show the eight deployed NAS services unchanged. No reboot, package upgrade,
deployment, main merge or destructive operation on existing databases occurred.

Current full-project hosted results are recorded after publication, separately from
the prior [recovery checkpoint results](2026-11-05-recovery-cli-github-final.md).
The prior full suites are not relabeled as new runs. The roadmap keeps Partial
classifications and distinguishes a real isolated rehearsal from production release.
