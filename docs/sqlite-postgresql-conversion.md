# SQLite to PostgreSQL conversion rehearsal

`aegis-admin rehearse-sqlite-to-postgres` copies a supported AegisNAS SQLite
snapshot into a **new private PostgreSQL schema** and verifies its contents. This
implements the isolated conversion rehearsal in NAS-0008. It does not change the
active configuration, stop services, activate PostgreSQL, or authorize a release.

## Run a rehearsal

Prepare a separate target configuration using the PostgreSQL connection and secret
reference policy in [PostgreSQL data plane](postgresql-data-plane.md). Production
TLS policy still applies; use `verify-full` and the intended CA/host identity.
The target role needs permission to create a schema and its tables/sequences.
Use a disposable database or a separately reviewed staging database first.

```bash
aegis-admin rehearse-sqlite-to-postgres \
  --config /secure/staging-postgres.yaml \
  --source-sqlite /var/lib/aegisnas/data.db \
  --target-schema aegis_conversion_review_001 > /secure/conversion-receipt.json
```

The schema name must begin with `aegis_conversion_`, followed by 1–40 lowercase
letters, digits or underscores. An existing schema is always refused. No `public`
schema import, overwrite, service activation or automatic cleanup option exists.
Use a new name for each attempt. Protect receipts and target data according to
your recovery/data-retention policy; the imported tables contain sensitive data.

## What is verified

- The existing source is opened read-only. SQLite `VACUUM INTO` captures committed
  WAL data in a private workspace; only that copy is migrated to the current schema.
  Both the source main file and expanded snapshot are limited to 8 GiB.
- The source version must be between 1 and the current migration version. SQLite
  integrity and foreign keys are checked after migration. Views/triggers, unknown
  tables, mismatched columns/primary keys, and tables without primary keys fail.
- The target schema is created exclusively and PUBLIC access is revoked. A schema
  advisory lock serializes competing conversions. The target connection excludes
  the caller's original search path. Existing schemas are not migrated or cleared.
- A single import transaction replaces only bootstrap rows in the newly created
  schema. Foreign keys are deferred while copying and explicitly validated before
  their original enforcement modes are restored. They are never disabled.
- Every table is compared using a row count and SHA-256 digest of ordered,
  type-normalized rows. Text primary keys use matching binary/C collation. Values,
  DSNs and credentials are withheld from failure messages and receipts.
- PostgreSQL sequences restart above both the greatest retained ID and SQLite's
  deleted-ID high-water mark. Sequence exhaustion fails. Transactional `ALTER
  SEQUENCE RESTART` participates in rollback of an unsuccessful import.

These mechanisms follow PostgreSQL's documented
[deferred constraint validation](https://www.postgresql.org/docs/current/sql-set-constraints.html)
and [transactional sequence restart](https://www.postgresql.org/docs/current/sql-altersequence.html).

## Precision and unsupported data

PostgreSQL timestamps have [microsecond resolution](https://www.postgresql.org/docs/current/datatype-datetime.html).
Its `REAL` type uses float32, while SQLite can retain a float64 value. The command
defaults to rejecting a row that would lose either kind of precision.

After reviewing that tradeoff for a rehearsal, explicitly add
`--allow-precision-loss` to truncate submicrosecond timestamp precision and round
`REAL` values to float32. The receipt counts both changes. Timestamps are normalized
to UTC; unzoned supported SQLite timestamps are interpreted as UTC. Overflow,
nonfinite numbers, invalid timestamps and ambiguous value representations still
fail. This option is not a general validation bypass.

The target uses the current compiled AegisNAS schema. Custom source indexes,
constraints and business rules are **not certified or reproduced** by this tool;
review such databases separately. Support for versions 1–current is a validation
range, not a claim that every historical release variant has been tested. Current
evidence covers a populated schema-1 source upgraded to 103 and a current schema-103
source. Exact platform versions and executed checks are in the linked reports.

## Failure and activation boundaries

A failure leaves the source and existing target schemas intact. The new private
schema, if created, is retained for inspection. Import errors roll back copied
rows and sequence changes; target DDL/bootstrap data may remain because the schema
migration phase precedes the import transaction. A lost connection during COMMIT
can have an uncertain outcome: inspect the retained schema and receipt before any
retry. Do not activate a failed or ambiguous result.

A success returns `status: verified_rehearsal` and
`production_activation_authorized: false`, with source snapshot hash, original and
target versions, per-table counts/digests, sequence values and precision changes.
Hashes are integrity evidence, not signatures. Live writes committed after the
snapshot are not replicated. The operator must separately plan source quiescing,
final synchronization, least-privilege application access, DSN/config changes,
service verification and rollback. Those activation, HA, outage, soak, full-image
security and hardware acceptance requirements keep NAS-0008/NAS-0116 Partial.

Regression commands:

```bash
# AEGIS_TEST_POSTGRES_DSN must point to a disposable database.
go test ./internal/db -count=1 -run 'TestConversion|TestSQLitePostgreSQLConversionLive'
go build -o build/conversion-bin/aegis-admin ./cmd/aegis-admin
python3 scripts/test_database_conversion_cli.py \
  --admin-bin build/conversion-bin/aegis-admin --output build/database-conversion
```

The Python fixture intentionally retains uniquely named schemas until the disposable
cluster/container is removed. CI publishes logs and receipts, excluding private
fixture databases and configurations. See the
[conversion execution report](reports/2026-11-05-conversion-readiness.md).
