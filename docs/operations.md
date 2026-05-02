# Operations Guide

## Service Management

During development, run commands from the repository root.

### Snap Deployments

```bash
snap start aegis-gateway
snap restart aegis-admin-api
snap logs aegis-admin-api -f
snap stop aegis-ai-lite
```

### Package Or VM Deployments

```bash
sudo systemctl restart aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api
sudo systemctl status aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api --no-pager
sudo journalctl -u aegis-admin-api -u aegis-portal -u aegis-session -n 100 --no-pager
```

### Development Commands

```bash
go run ./cmd/aegis-admin migrate --config configs/config.yaml
go run ./cmd/aegis-admin seed --config configs/config.yaml
go run ./cmd/aegis-admin-api run --config configs/config.yaml
```

## Admin Access Workflow

Operators can now sign in with either:

- an admin API token
- admin SSO through OIDC or SAML

Keep token login available as break-glass access even when SSO is enabled.

The normal workflow is:

1. Sign in with SSO or a bootstrap/admin token.
2. Edit objects from the relevant page.
3. Each create, edit, or delete is staged first.
4. Use the pending changes bar to validate.
5. Apply staged changes when validation passes.
6. Use `Revisions` to roll back a bad apply.

Current operator pages in the UI:

- Dashboard
- Access Settings
- Admin Access
- VLANs
- Portal Profiles
- Users
- Devices
- Guest Requests
- Vouchers
- Roles
- Bandwidth
- Policies
- Identity Sources
- RADIUS Clients
- Sessions
- Alerts
- Revisions
- Backups
- AI Insights

Role visibility is now enforced in the UI for:

- `super_admin`
- `ops_admin`
- `guest_admin`
- `read_only`

## Runtime Monitoring

Health endpoints are registered by each daemon. In a package-based deployment, the common checks are:

```bash
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8081/health
curl -fsS http://127.0.0.1:8082/health
curl -fsS http://127.0.0.1:8083/health
curl -fsS http://127.0.0.1:8085/health
curl -fsS http://127.0.0.1:8087/health
```

The dashboard is now the primary operator surface for:

- service health
- deployment profile and capability state
- upstream AAA status
- runtime shaping state
- admin SSO runtime state
- SIEM export runtime state
- controller automation runtime state

Telemetry also generates alerts into the `alerts` table. Alerts can be acknowledged from the admin UI.

The AI engine stores recommendations in `ai_recommendations`. These remain advisory and never gate authentication, policy enforcement, or traffic admission.

## Guest, Onboarding, And Access Operations

Current day-two operator workflows include:

- approve or reject guest self-registration requests from `Guest Requests`
- review device inventory and certificate bundles from `Devices`
- review or update delegated-admin mappings from `Admin Access`
- terminate live sessions from `Sessions`
- acknowledge health and integration alerts from `Alerts`

For captive portal and guest workflow investigations, use the focused runbook in [Login And Captive Portal Test Runbook](login-test-runbook.md).

## Logs

Logs are structured JSON.

For snap deployments:

```bash
snap logs aegis-admin-api -f
```

For systemd deployments:

```bash
sudo journalctl -u aegis-admin-api -u aegis-portal -u aegis-session -u aegis-radius -u aegis-gateway -f
```

For file logging, paths are set by `logging.output` in the config. File logs rotate at 10 MB, keep five backups, and compress old files.

For appliance login, portal, onboarding, and AAA investigations in Ubuntu VM or package-based deployments, capture a separate-file debug bundle with:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario portal-local-failure
```

Recommended scenario names now include:

- `portal-local-postlogin`
- `portal-selfreg-postapprove`
- `portal-voucher-postlogin`
- `device-onboarding-postenroll`
- `admin-sso-callback`
- `controller-sync-warning`

## Integration Operations

When integrations are enabled, operators should verify:

- admin SSO redirect and callback behavior
- SIEM export health and last delivery message
- controller automation last sync message
- MDM or compliance posture synchronization status
- external CA enrollment reachability when `ca_mode: external`

Those states are surfaced in the dashboard and reflected in alerts when delivery or sync degrades.

## Backup And Restore

Use the CLI for full appliance backup and the admin UI for config-only JSON backup. See [Backup and Restore Procedures](backup-restore.md).

Run at least one restore drill before production sign-off.

## Software Updates

Snaps refresh automatically by default. For controlled maintenance windows:

```bash
snap set system refresh.timer=sun,02:00-04:00
```

For VM or package-based deployments from a local clone, pull the updated repo and follow the relevant runbook for rebuild, reinstall, and service restart.

Before updating production devices:

1. Export a config JSON backup.
2. Create a full CLI backup.
3. Confirm the management path is reachable.
4. Confirm break-glass admin token access still works before changing SSO settings.
5. Apply the update.
6. Check health, sessions, RADIUS auth, portal login, onboarding, alerts, and dashboard integration state.
