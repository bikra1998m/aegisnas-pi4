# Historical context reconciliation addendum — 2026-10-26

The original archive was previously streamed read-only (169,946 records, zero
parse errors; SHA-256 `a50a2633f7670a564524487d9edbe6cc650e7bdfc33f1dd9748e9b6cde4c3361`).
This turn reused the [archived reconciliation](2026-10-15-history-reconciliation.md)
and current code/evidence rather than loading the archive again or treating plans
as completed implementation. All 98 inherited report files remain byte-preserved.

The AAA/NAS product boundary, stable feature IDs, dependency sequencing, advisory
AI separation, hardware-tier certification and evidence-based Partial telecom
classifications remain unchanged. No historical instruction was used to reverse
the newer admission, PostgreSQL or security improvements.

## Newly reconciled assumptions

1. Earlier PostgreSQL API HTTP-200 smoke results did not prove that SQLite ZIP
   download or file-copy rehearsal protected PostgreSQL data. Code inspection
   exposed that scope mismatch. The API now rejects the backup path with 409 and
   labels PostgreSQL rehearsal unsupported; SQL transaction rollback tests remain
   valid and distinct from production backup/restore certification.
2. A copied SQLite main file can omit committed WAL pages. Rehearsal now uses a
   consistent snapshot, with a test keeping committed migration state in WAL.
3. Valid ZIP/schema metadata alone did not authenticate recovery data. The new
   keyed envelope and exact trusted digest protect staging; legacy production
   activation integration remains missing and is not promoted by local tests.
4. Linux fixture setup inherited a group-writable umask. Positive tests now
   create private directories; the production permission policy was preserved.
5. Deployed readiness had one 20-second timeout before a successful same-deadline
   retry. That failure remains evidence rather than being erased by the retry.

Earlier 1,419-pass Windows and older full Ubuntu/browser/database/packet results
are historical executions, not new all-roadmap certification. The current
reports explicitly separate epochs and scopes. The only post-runtime-test code
change was the OpenAPI 409 description and matching contract assertion; it had
focused validation and rebuilt API binaries.
