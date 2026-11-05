# PostgreSQL evidence reconciliation

**NOT TESTED in this admission-only continuation.** No database implementation, schema, connection policy or FreeRADIUS configuration was changed. All previously tested Go/dependency inputs remain identical, and raw evidence/report hashes were verified.

Retained, actually executed earlier evidence:

- October 22 PostgreSQL 14.24 on Ubuntu and 18.6 on Windows: 152 passing test/subtests per matrix. Schema 102, repeated migrations/seed, audit, transactions, integer-width upgrade and shared service lifecycles were covered.
- October 22 isolated Ubuntu TLS/logical restore: 25 checks, including wrong-root/hostname rejection, 181 table counts, schema and audit preservation.
- Earlier October 23 isolated FreeRADIUS 3.0.26/PostgreSQL 14: 22 checks including actual SQL-backed packets, SCRAM/TLS enforcement, database outage/reconnect and negative certificates. These used the actual generated module plus a diagnostic query.

**NAS-0008 remains Partial.** Production accounting/post-auth queries and packet-to-session reconciliation are unfinished; diagnostic SELECT success is not accounting acceptance. PostgreSQL systemd secret deployment, SQLite conversion, application-wide outage recovery, production backup/HA, soak and tiered pool performance remain open. No production PostgreSQL deployment or database reset occurred.

See [October 23 PostgreSQL report](2026-10-23-continuation-postgresql.md), [October 22 integration report](2026-10-22-production-postgresql.md), and [NAS-0008 checklist](../nas-0008-release-certification-checklist.md).
