# Backup and Restore Procedures

Backups have two layers:

- Full appliance archive from the CLI: database, config file, and checksum manifest.
- Config JSON from the admin UI: users, vouchers, roles, bandwidth profiles, portal profiles, policies, identity sources, and RADIUS clients.
- Upgrade rollback package: version-aware config and SQLite snapshot used specifically for upgrade rollback decisions and rehearsals.

## CLI Backup

```bash
aegis-admin backup /backups/aegisnas-$(date +%Y%m%d-%H%M%S).tar.gz --config /etc/aegisnas/config.yaml
```

The archive includes:

- `data.db`
- `config.yaml` when the configured file exists
- `manifest.json` with SHA-256 checksums

## CLI Restore

1. Stop AegisNAS services.
2. Copy the archive to the appliance.
3. Run restore:

```bash
aegis-admin restore /backups/aegisnas-20260417-120000.tar.gz --config /etc/aegisnas/config.yaml
```

The restore flow extracts to a temporary directory, verifies `manifest.json`, runs SQLite `PRAGMA integrity_check`, asks for confirmation, and then replaces the current database and config file.

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
