# Backup and Restore Procedures

Backups have several scopes:

- Local SQLite archive from the CLI: database, config file, and checksum manifest; this is not a full appliance image.
- Config JSON from the admin UI: users, vouchers, roles, bandwidth profiles, portal profiles, policies, identity sources, and RADIUS clients.
- Upgrade rollback package: version-aware config and SQLite snapshot used specifically for upgrade rollback decisions and rehearsals.

## CLI Backup

```bash
aegis-admin backup /backups/aegisnas-$(date +%Y%m%d-%H%M%S).tar.gz --config /etc/aegisnas/config.yaml
```

The archive includes:

- `data.db`
- `config.yaml` from the configuration actually selected by the CLI, including `./config.yaml`; an unreadable selected file fails the backup
- `manifest.json` with SHA-256 checksums

The CLI uses SQLite `VACUUM INTO` to capture a consistent database snapshot,
including committed WAL transactions, without copying a possibly stale main
database file. See the [SQLite snapshot documentation](https://www.sqlite.org/lang_vacuum.html).
This does not make the separate config file and database one coordinated snapshot.
The destination must be new: an existing archive is never overwritten. Archives
are created with mode `0600` on Linux. Compressed and expanded payloads are each
limited to 512 MiB; configuration is limited to 4 MiB and the manifest to 64 KiB.
Larger databases require a separately reviewed recovery procedure. A failed write
may leave a partial output; retain its failure log and choose a new output path.

Both commands reject PostgreSQL before opening a database or creating an archive.
Use the separately validated PostgreSQL logical/managed recovery procedure for
that data plane. These tar archives are unencrypted and their checksums are not
authentication. Only restore trusted local archives. See
[authenticated recovery staging](authenticated-recovery-staging.md) for the
separate encrypted staging path and its remaining activation limitations.

## CLI Restore

1. Stop every SQLite client, including AegisNAS services and external readers or writers. Complete checkpoint/recovery through SQLite first; do not delete WAL, SHM or journal files manually.
2. Copy the archive to the appliance.
3. Run restore:

```bash
aegis-admin restore /backups/aegisnas-20260417-120000.tar.gz --config /etc/aegisnas/config.yaml
```

The restore flow validates a bounded archive in a private temporary directory,
requires exact manifest coverage, checks SQLite integrity and validates the
recovered config before asking for `yes`. Unknown or duplicate entries, links,
special files, malformed manifests, corrupt gzip trailers and trailing streams
are rejected. The recovered config must keep the current SQLite database path.
Destination directories must already exist, with no symlink components. Config
and database destinations must be distinct files.

Restore refuses existing `-wal`, `-shm` or `-journal` sidecars. Their absence does
not prove that clients have stopped; the operator must enforce that requirement.
All replacement files and private `.aegis-restore-before-*` safety copies are
prepared beside their destinations before replacement begins. Ordinary in-process
replacement failures trigger compensation for files already replaced. Successful
restores retain safety copies for the operator's retention policy. Review the
config and ownership/access permissions before restarting services; files are
created by the invoking account with Linux mode `0600`. Windows ACLs are not
certified by these permission tests.

This is an offline, operator-controlled procedure, not a power-loss-safe atomic
database/config transaction or authenticated production activation. Cross-service
quiescing, coordinated activation and other legacy restore entry points remain
open in NAS-0116. Executed Windows/Ubuntu evidence is in the
[November 5 recovery report](reports/2026-11-05-recovery-cli-readiness.md).

## Admin UI Config Backup

1. Sign in to the admin UI with an API token.
2. Open `Backups`.
3. Select `Download JSON`.

This produces `aegisnas-config-backup.json`. It is intended for configuration migration or quick recovery, not raw session/history preservation.

## Admin UI Config Restore

1. Open `Backups`.
2. Choose a JSON backup exported by the admin UI.
3. Select `Upload And Restore`.

The admin API creates a safety config revision before importing the JSON. If the restored config is wrong, use `Config Revisions` to roll back.

## Upgrade Rollback Package

The upgrade rollback package is the preferred pre-upgrade safety artifact.

Use it when you want:

- schema-aware rollback context
- compatibility inspection before restore
- a guided online restore path
- a clean offline restore workspace for a lab drill

Create it from the CLI:

```bash
sudo /opt/aegisnas/bin/aegis-admin create-upgrade-rollback-package \
  --config /etc/aegisnas/config.yaml \
  --output /var/tmp/aegisnas-upgrade-rollback.zip
```

Or download it from `Backups` in the admin UI.

Inspect it before any restore:

```bash
sudo /opt/aegisnas/bin/aegis-admin inspect-upgrade-rollback-package \
  --config /etc/aegisnas/config.yaml \
  --input /var/tmp/aegisnas-upgrade-rollback.zip
```

For the full operator workflow, including rehearsal and offline restore, use [Upgrade Rollback Runbook](upgrade-rollback-runbook.md).

## Operational Rules

- Store backup archives off-device; microSD cards are not durable enough for the only copy.
- Protect backups as secrets because they include user hashes, vouchers, and RADIUS client secrets.
- Protect upgrade rollback packages as secrets because they include live config and database contents.
- Test restore on a lab device before relying on a production backup schedule.
- Keep at least one known-good config JSON from after initial deployment and after every large policy change.
