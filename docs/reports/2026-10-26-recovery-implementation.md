# Current implementation audit — 2026-10-26

**Implemented and tested; NAS-0116 remains Partial.** This continuation began
from HEAD `7004511cfbea5f30d53db9b6ac768e059d7cfaf1`, with 245 modified and 134
untracked full-status entries. Existing work was preserved. No reset or broad
cleanup was performed. The final exact paths/status are recorded separately.

## Functionality

- New administrative CLI commands create encrypted SQLite recovery snapshots
  and authenticate/stage a selected snapshot using a protected random 32-byte
  key, caller-provided recovery context and independently approved sealed digest.
- Standard Go AES-256-GCM handles random nonces. No new cryptographic dependency,
  password derivation, invented release signature or unsigned fallback was added.
- ZIP parsing now bounds compressed and expanded content, restricts entries,
  rejects duplicates/special files and unsupported manifests, and bounds CLI reads.
- Extraction requires a new private directory, uses a confined filesystem handle,
  and creates files exclusively. Existing backups/workspaces are not overwritten.
- Linux key paths reject unsafe ownership/write modes, symbolic/hard links and
  non-regular files. Windows verifies logic, not Linux ownership or Windows ACL policy.
- Multipart recovery uploads are capped before parsing and temporary upload files
  are removed after reading. PostgreSQL raw SQLite backup downloads now return 409.
- PostgreSQL upgrade rehearsal no longer examines a local SQLite file. SQLite
  rehearsal uses a consistent snapshot including committed WAL pages.
- The actual CLI fixture, CI integration, OpenAPI 409 response and operational
  guide document and test the supported behavior. Recovery keys are never API inputs.

## Changes and verification scope

The [change ledger](2026-10-26-recovery-changes.csv) lists exactly 26 changed/new
implementation, test, workflow and guide files relative to the continuation
baseline, including before/after SHA-256. There are 19 modified inherited files
and seven new files. Separate generated reports are not counted in those 26.
All other baseline files and all 98 inherited reports are preserved.

Initial full affected-package tests preceded the final rehearsal fixes. Those
fixes received complete upgrade-suite and focused API/support-bundle regression
runs on both OSes plus actual SQLite/PostgreSQL API testing. The only later code
change adds the OpenAPI 409 description, verified by the contract test and API
builds on all targets. The final API binaries were not used to repeat the entire
live smoke solely for that documentation field. Source-epoch hashes are retained.

## Limits

The new commands stage recovery data; they do not implement a transaction across
services, config, database and binaries. Legacy raw ZIP restore paths remain lab
workflows. Snapshot compatibility/operator selection, production quiescing,
enforcement at every restore entry point, key governance and power-loss recovery
still require work. PostgreSQL backup is explicitly unsupported by these SQLite
commands. No maximum-size/Pi memory capacity or HA certification is claimed.

See [the operational guide](../authenticated-recovery-staging.md) for exact
format, permissions, limits, key-use bounds, commands and remaining integration.
