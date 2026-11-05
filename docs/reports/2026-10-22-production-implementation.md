# Current implementation audit

NAS-0008 is the next feasible independent work item after NAS-0116: it depends on NAS-0002, while production release still depends on NAS-0116. Both remain Partial.

Implemented shared SQLite/PostgreSQL database lifecycle fixtures; portable Boolean parameters/predicates, nullable timestamps, UTC reads, generated IDs and offsets, aggregate/upsert fixes and PostgreSQL 14 aliases. SQL repairs include DB helpers and authorization, RADIUS, enforcement, controller, LDAP, onboarding and guest services. These tests verify stored/runtime behavior, not external device enforcement.

Schema 102 uses BIGINT for SQLite-compatible 64-bit counters and widens existing migration-owned INTEGER columns transactionally. Tests preserve old values, accept `1<<40`, leave unrelated tables unchanged and repeat migration. Existing-data ALTER TYPE can lock/rewrite tables and needs maintenance-window rehearsal; no deployed database was migrated.

The date-function parser preserves SQL literals/comments and nested calls. Application connection policy enforces configured SSL mode over DSN conflicts, UTC and connection/statement timeouts. Charging hashes match PostgreSQL microsecond storage. MFA/WebAuthn expiry rejects invalid, expired and exact-boundary timestamps. SQLite HA file create/import/activate paths reject PostgreSQL before file access; its download API returns 409. PostgreSQL HA is not implemented by that guard.

Added PostgreSQL 14/18 CI matrix and expanded isolated real API smoke coverage. Hosted Actions execution is NOT TESTED. Preserved prior release-security API/UI/admission changes. Raised Go to 1.26.10 and locked follow-redirects to 1.16.1 after fresh advisories; browser production assets are byte-identical after the npm patch.

Exact modified/new paths and before/after hashes: [change ledger](2026-10-22-production-changes.csv), [source state](2026-10-22-production-source-state.json). The ledger separates inherited changes from changes since October 15 and October 22. All changes remain uncommitted. No reset or unrelated change removal occurred.

New review gap: the existing FreeRADIUS PostgreSQL renderer emits host/port/user/database fields but does not propagate DSN SSL parameters or the application's connection policy. Its accounting/postauth template also requires live query integration proof. Application-driver TLS PASS therefore does not certify the FreeRADIUS SQL path. This is an unresolved software/integration blocker, not merely missing hardware. FreeRADIUS documents PostgreSQL SSL connection parameters in its [3.2.8 SQL module configuration](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_8/raddb/mods-available/sql).
