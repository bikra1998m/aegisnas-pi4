# Operations Guide

## Service Management

During development, run commands from the repository root.

Common snap operations:

```bash
snap start aegis-gateway
snap restart aegis-admin-api
snap logs aegis-admin-api -f
snap stop aegis-ai-lite
```

Development commands:

```bash
go run ./cmd/aegis-admin migrate --config configs/config.yaml
go run ./cmd/aegis-admin seed --config configs/config.yaml
go run ./cmd/aegis-admin-api run --config configs/config.yaml
```

## Admin UI Workflow

1. Sign in with an API token.
2. Edit objects from the relevant page.
3. Each create, edit, or delete is staged first.
4. Use the pending changes bar to validate.
5. Apply staged changes when validation passes.
6. Use `Config Revisions` to roll back a bad apply.

Manual pages available in the UI:

- Dashboard
- VLANs
- Portal profiles
- Users
- Vouchers
- Roles
- Bandwidth profiles
- Policies
- Identity sources
- Sessions
- Alerts
- Config revisions
- Backups
- AI recommendations

## Monitoring

- Health endpoints are registered by each daemon.
- Telemetry generates alerts into the `alerts` table.
- Alerts can be acknowledged from the admin UI.
- The AI engine stores recommendations in `ai_recommendations`; these are advisory and never gate authentication.

## Logs

Logs are structured JSON. For snap deployments, view logs with:

```bash
snap logs aegis-admin-api -f
```

For file logging, paths are set by `logging.output` in the config. File logs rotate at 10 MB, keep five backups, and compress old files.

For appliance login, portal, and AAA investigations in Ubuntu VM or package-based deployments, capture a separate-file debug bundle with:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario portal-local-failure
```

See [Login And Captive Portal Test Runbook](login-test-runbook.md) for the recommended pre-login, post-login, failure, and logout capture points.

## Backup and Restore

Use the CLI for full appliance backup and the admin UI for config-only JSON backup. See [Backup and Restore Procedures](backup-restore.md).

## Software Updates

Snaps refresh automatically by default. For controlled maintenance windows:

```bash
snap set system refresh.timer=sun,02:00-04:00
```

Before updating production devices:

1. Export a config JSON backup.
2. Create a full CLI backup.
3. Confirm the management VLAN path is reachable.
4. Apply the update.
5. Check health, sessions, RADIUS auth, portal login, and alerts.
