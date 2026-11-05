# PostgreSQL integration — October 23

**PASS: 22 isolated FreeRADIUS/PostgreSQL checks. NAS-0008 remains Partial.**

FreeRADIUS 3.0.26 loaded the real matching `rlm_sql_postgresql` driver and used the module produced by current Go code. PostgreSQL required SCRAM for the fixture role and rejected cleartext connections for that role. Certificate path with spaces and a password containing quotes, backslashes, dollar expansions and URI punctuation worked through real authentication.

The diagnostic SQL-backed RADIUS request returned `UTC|1500ms|true`; this proves the live connection had the configured startup settings and TLS, even though the DSN requested weaker settings. Valid requests received Access-Accept. Stopping only the owned fixture database caused Access-Reject, and restarting it recovered Access-Accept. Wrong CA and wrong hostname caused module startup failure with the expected certificate error. Fixture PostgreSQL was stopped successfully afterwards.

The first fixture attempt FAILED because the minimal harness omitted the `expr` module required for `tolower`. After adding that standard module, attempt 2 passed. Attempt 3 reran the final code and authoritative-option checks and passed. The failed attempt and successful retries are retained separately.

NOT TESTED in this fixture: generated production accounting/post-auth writes, session reconciliation, production roles/PKI, customer data conversion, multi-service outage/HA, soak or production cutover. The generated accounting/post-auth sections still have references without complete production queries; no full packet-accounting certification is claimed.

Historical October 22: PostgreSQL 14.24 and 18.6 lifecycle matrices each 152 PASS; schema 102, seed/audit/rollback and integer-width conversion; 25 application TLS/logical-restore checks, 181 table counts preserved; 220 real API checks per tested backend/platform. No schema or shared database runtime code changed in this continuation. These results remain historical.

Repeatable fixture: [runtime guide](../postgresql-runtime-validation.md), [script](../../scripts/test_freeradius_postgres.py). Primary protocol references: [FreeRADIUS PostgreSQL driver](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_0_26/src/modules/rlm_sql/drivers/rlm_sql_postgresql/rlm_sql_postgresql.c), [libpq connection syntax](https://www.postgresql.org/docs/14/libpq-connect.html).
