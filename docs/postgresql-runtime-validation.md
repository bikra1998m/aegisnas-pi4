# PostgreSQL runtime verification and recovery boundaries

The [latest accounting implementation](postgresql-radius-accounting.md) adds
schema 103 and an opt-in `--accounting` packet fixture. Its
[execution report](reports/2026-10-23-sql-accounting-readiness.md) separates
durable packet tests, disposable SQL compatibility matrices, failures and
production blockers. The October 22/earlier October 23 counts below are historical.

NAS-0008 remains Partial. The October 22 continuation extends actual runtime SQL
coverage beyond the earlier migration, seed, audit and NAS-client tests. Executed
results and unsuccessful attempts are recorded in
[the production-validation report index](reports/2026-10-22-production-readiness.md).

## Shared database matrix

Normal `go test ./...` retains SQLite fixtures. Setting
`AEGIS_TEST_RUNTIME_POSTGRES_DSN` selects a real PostgreSQL server for the shared
runtime fixtures. Each fixture creates and drops only its own uniquely named
schema. `AEGIS_TEST_POSTGRES_DSN` separately enables the migration, seed, rollback,
pool-timeout and existing-integer-upgrade integration test. These variables must
point to a disposable test database with CREATE SCHEMA permission.

```powershell
# Supply disposable test DSNs through the environment, not committed files.
go test ./internal/db -count=1 -json -timeout=25m -skip '^TestMigrate|^TestSeed|^TestVendorIdentity'
```

The skipped name patterns select SQLite-specific fixtures; the ordinary full
regression run executes them separately. A missing live DSN is an explicit test
skip, never PostgreSQL evidence. The CI matrix targets PostgreSQL 14 and 18;
creating the workflow does not mean a hosted run has passed.

The matrix covers populated accounting, charging, session, guest, voucher,
identity, authentication-challenge, policy, client, vendor-pack and spool
lifecycles. It verifies 64-bit counters and PostgreSQL microsecond precision in
charging integrity hashes. It does not establish live device enforcement for
those features. Parameter-free system GET smoke tests similarly verify API
execution, not external controller or hardware behavior.

## TLS and restore rehearsal

The local VM rehearsal uses an owned loopback-only PostgreSQL cluster, a
short-lived fixture certificate and dedicated `aegis_smoke_*` databases. It checks
the actual application connection with `verify-full`, rejection of an untrusted
root and a mismatched server address, negotiated TLS, and a logical dump restored
into a new empty test database. It compares all application table counts, schema
version and a known audit fixture. Private fixture keys and database dumps stay
outside Git.

This supplies lab evidence only. Production certificate issuance, role privileges,
secret rotation, backup encryption/retention, managed snapshots and customer
recovery objectives require separate validation. PostgreSQL documents certificate
and hostname checks in [SSL support](https://www.postgresql.org/docs/18/libpq-ssl.html)
and fail-on-error restoration in [pg_restore](https://www.postgresql.org/docs/14/app-pgrestore.html).

For a production runbook, use a restricted libpq service entry and secret provider,
create a new empty restore target, restore with `pg_restore --exit-on-error`, then
verify schema, application invariants and access controls before any cutover.
Never point a rehearsal at the deployed database or restore over it. The existing
SQLite appliance restore script is not a PostgreSQL migration or rollback tool.

## Isolated FreeRADIUS PostgreSQL TLS fixture

`scripts/test_freeradius_postgres.py` runs a separate FreeRADIUS process and a new
private PostgreSQL 14 cluster on random loopback ports. It requires a matching
extracted SQL module, the PostgreSQL binary/library tree, and a Linux test binary
built with `go test -c ./internal/radius -o radius.test`. Example:

```sh
python3 scripts/test_freeradius_postgres.py \
  --root /private/new-fixture-directory \
  --pg-root /private/extracted-postgresql \
  --module-root /private/matching-freeradius-modules \
  --generator-test-binary /private/radius.test
```

The root must not exist. No system package installation, deployed configuration
change or service restart is performed. Fixture processes stop in cleanup and
all result/failure logs are preserved. Fixture credentials and keys are not
production secrets. The script tests the actual generated module URI with SCRAM,
TLS `verify-full`, escaped credentials, a certificate path containing a space,
authoritative UTC/timeout options, real Access-Accept/Reject packets, an isolated
database outage/reconnect, and wrong-root/hostname rejection. Its diagnostic SQL
query does not exercise production accounting writes or session reconciliation.
October 23: 22 checks PASS; an earlier missing `expr` fixture-module failure is
preserved separately. Hosted CI execution of this fixture is NOT TESTED.

## Remaining gates

- Existing SQLite data conversion, reconciliation and rollback rehearsal.
- Production FreeRADIUS PostgreSQL module deployment and generated
  accounting/post-auth and packet-to-session acceptance. The queries are now
  implemented; production installation, broader service integration and customer
  acceptance remain open. See the accounting report for current lab evidence.
- PostgreSQL-aware appliance backup orchestration and failover; file replication
  is explicitly rejected for PostgreSQL.
- Application-wide outage/reconnection, long accounting/session soak and representative
  Lite/Branch/Enterprise load and pool benchmarks.
- Systemd/file-secret deployment, production PKI/role review and customer acceptance.
- NAS-0116 signed artifact admission, production activation and authenticated
  rollback, alongside dependency and OS vulnerability gates.

Do not use an HTTP 200 status, a configuration readiness flag, or a successful
empty-schema migration as evidence that these gates are complete.
