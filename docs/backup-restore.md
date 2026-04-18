# Backup and Restore Procedures

Backups have two layers:

- Full appliance archive from the CLI: database, config file, and checksum manifest.
- Config JSON from the admin UI: users, vouchers, roles, bandwidth profiles, portal profiles, policies, identity sources, and RADIUS clients.

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

## Operational Rules

- Store backup archives off-device; microSD cards are not durable enough for the only copy.
- Protect backups as secrets because they include user hashes, vouchers, and RADIUS client secrets.
- Test restore on a lab device before relying on a production backup schedule.
- Keep at least one known-good config JSON from after initial deployment and after every large policy change.
