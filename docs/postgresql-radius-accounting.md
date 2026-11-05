# PostgreSQL accounting and session reconciliation

NAS-0008 remains **Partial**. The generated PostgreSQL module now implements
accounting and post-auth writes when `radius.sql_accounting.enabled` is true.
This is an implementation slice, not production certification or authorization
to activate an unsigned release. Apply schema 103 in an isolated rehearsal before
using the new queries; the existing deployed VM has not been migrated.

## Packet processing

The generated default virtual server uses the installed FreeRADIUS `acct_unique`
policy during pre-accounting. The SQL writer scopes that identifier by the actual
packet source and NAS address, and gives the resulting application session its
own `sql-` identifier. This also separates identical Class/session identifiers
from different NAS addresses. Changing that identity tuple creates another row;
it is not an automatic roaming correlation policy.

- Start, Interim-Update and Stop upsert the latest `radacct` snapshot. Missing
  Start packets are handled using event time minus reported session duration.
- Older interims and updates after Stop do not replace newer or terminal data.
  A late Stop closes the row while retaining more recent counters. Successful
  no-op queries are acknowledged so obsolete retransmissions can stop.
- Accounting-On/Off close only eligible open rows for the same NAS and packet
  source; a session newer than the reboot event remains open.
- Missing/unsupported status or missing session identifiers receive no accounting
  acknowledgement. SQL failure likewise suppresses the Accounting-Response.
- Event-Timestamp is preferred; reception time minus Acct-Delay-Time is the
  fallback. The generated connection enforces UTC, configured timeouts and TLS.
- Low 32-bit octets, gigawords and exact unsigned decimal totals are stored
  separately. PostgreSQL NUMERIC arithmetic avoids signed BIGINT overflow.
- IPv4/IPv6, prefix, first route, class and multi-session metadata are retained.
  This does not implement a complete ordered list of repeated route attributes.

Post-auth stores the outcome and selected request metadata for accepts/rejects.
It never inserts passwords, challenge responses or failure-message text. Failure
to store an accept audit record rejects the authentication in this configured
path. Inner-tunnel authentication and all EAP method combinations still require
separate acceptance testing.

## Concurrent reconciliation and migration

Schema 103 adds `aegis_ingest_revision` (BIGINT) and `aegis_packet_source` to
`radacct`, with defaults that retain existing rows. Every writer update advances
the revision. Reconciliation applies the snapshot through the existing event
ledger and session logic, then projects derived counter, route and correlation
metadata only if that revision is still current. The final acknowledgement has
the same revision condition. Applying an old snapshot cannot erase or acknowledge
a packet that arrived during processing; the newer row remains pending.

The SQL-source event path no longer writes its old counters back into `radacct`.
Other accounting sources retain their existing mirror behavior outside snapshot
reconciliation. Provider source labels on polled snapshots are preserved, and
those snapshots are also protected from writing back over a newer packet. Tests inject a
new packet between snapshot ingestion and application, and exercise the upgrade
with pre-existing data on SQLite and PostgreSQL.

`radacct` is a latest-state table. Several packets can coalesce before the next
poll. This integration does **not** establish a lossless packet-level billing
ledger, multi-consumer exactly-once delivery or a durable outage spool. Those
require independent acceptance criteria and tests.

## Verification and operating boundaries

Build the Linux radius test binary and invoke
`scripts/test_freeradius_postgres.py --accounting`, supplying the normal fixture
arguments described in [runtime validation](postgresql-runtime-validation.md)
plus `--accounting-policy /private/readable-copy-of-policy.d/accounting`.
The policy must match the installed FreeRADIUS release. The fixture uses random
loopback ports, a new owned PostgreSQL cluster, fixture-only SCRAM credentials
and certificates, and the actual generated SQL/unlang. It preserves process
timeouts and partial output. No deployed configuration or service is modified.

`--database-test-binary` optionally runs the shared SQL matrix in owned schemas.
That matrix creates many thousands of temporary relation/index files; run it on
suitable storage, separately from latency/durability tests. A compatibility run
using a disposable cluster with `fsync=off` cannot demonstrate crash recovery,
durability or production performance. The packet fixture uses normal durability
settings. Hosted workflow configuration is not proof of a successful hosted run.

Shared PostgreSQL fixtures allow up to 60 seconds for their owned-schema teardown
transaction; cleanup must still succeed. Production connection and statement
timeouts are unchanged. The PostgreSQL 14 run also exposed an ignored summary
query error: open identity-source counts now use a named derived table, propagate
query errors, and have a populated distinct-source assertion on both backends.

The fixture role has access only to the accounting/authentication tables and
their sequences, and cannot create schema objects or write application sessions.
Production role provisioning, credential rotation, systemd secret providers,
PKI, module installation, service-wide outage handling, existing-data conversion,
backup/HA, soak and customer acceptance remain open. The SQLite direct FreeRADIUS
SQL writer remains outside this PostgreSQL implementation.

Protocol and configuration references:
[RFC 2866](https://www.rfc-editor.org/rfc/rfc2866.html) and
[FreeRADIUS 3.0.26 PostgreSQL configuration](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_0_26/raddb/mods-config/sql/main/postgresql/queries.conf).
