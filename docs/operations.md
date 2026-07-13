# Operations Guide

## RadSec

Use [radsec.md](radsec.md) for the RFC 6614 mTLS architecture, certificate
requirements, RADIUS/1.1 capability gating, failure behavior, and deployment
procedure. Run `scripts/radsec-smoke-test.sh` after installing credentials and
before accepting production traffic.

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

## Secret Provider Operations

Use [secret-providers.md](secret-providers.md) for the NAS-0007 secret reference
model. Before production sign-off, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/secret-providers | jq '.status, .summary'
```

All required `env:` and `file:` refs must resolve, and inline secret material
must be migrated out of YAML and SQLite. Existing inline secrets remain
backward-compatible during upgrade, but production readiness marks them as
blocking when `security.secrets.production_require_references` is enabled.

## PostgreSQL Data-Plane Operations

Use [postgresql-data-plane.md](postgresql-data-plane.md) for NAS-0008
configuration, migration, FreeRADIUS SQL, and backup notes. Before enterprise
production sign-off, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/database | jq '.status, .active, .warnings'
```

Production deployments should use `database.backend: postgres`,
`database.dsn_ref`, and TLS `sslmode: verify-full` or `verify-ca`. SQLite remains
valid for lite/lab deployments but is reported as degraded for enterprise
readiness.

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
- review guest lifecycle counts, delivery failures, and recent request trends from `Guest Requests`
- review sponsor backlog, invite failures, and approval timing from `Guest Requests`
- review device inventory and certificate bundles from `Devices`
- review or update delegated-admin mappings from `Admin Access`
- terminate live sessions from `Sessions`
- acknowledge health and integration alerts from `Alerts`

For captive portal and guest workflow investigations, use the focused runbook in [Login And Captive Portal Test Runbook](login-test-runbook.md).

For managed interface, gateway, DNS, DHCP, firewall, and rollback work in `Access Settings`, use the dedicated [Edge Network Operations Guide](edge-network-operations.md).

For active/standby deployment, shared replication, VIP takeover, and HA history, use the dedicated [HA Active/Standby Runbook](ha-active-standby-runbook.md).

For version-aware upgrade rollback package creation, inspection, rehearsal, and offline restore, use the dedicated [Upgrade Rollback Runbook](upgrade-rollback-runbook.md).

For the live admin API contract, OpenAPI download path, and role-hint guidance, use [Admin API Guide](admin-api.md).

For one-shot cross-domain operational snapshots that combine network, HA, upgrade, and integration state, use the diagnostics report from `Backups` or `GET /api/v1/system/diagnostics-report`.

For recurring redacted troubleshooting bundles without waiting for a manual click during an incident, enable scheduled support bundle exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/support-bundle-exports`.

For recurring report capture without manual operator action, enable scheduled diagnostics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/diagnostics-exports`.

For durable controller, MDM sync, and posture automation history, use `Backups` or `GET /api/v1/system/integration-history`.

For recurring integration capture without manual export timing, enable scheduled integration exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/integration-exports`.

For a durable upstream AAA probe timeline beyond the live dashboard badge, use `Backups` or `GET /api/v1/system/upstream-aaa-history`.

For a durable record of operator-visible admin actions, exports, guest approvals, network changes, HA activations, and upgrade work, use `Backups` or `GET /api/v1/system/audit-history`.

For recurring audit capture without relying on manual export timing, enable scheduled audit exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/audit-exports`.

For guest lifecycle summary, delivery-state visibility, and JSON or CSV handoff artifacts without leaving the approval console, use `Guest Requests` or `GET /api/v1/system/guest-lifecycle`.

For sponsor-approval backlog, invite-delivery failures, and approval-to-completion timing without leaving the guest workflow page, use `Guest Requests` or `GET /api/v1/system/guest-delivery-analytics`.

For top rejection reasons, sponsor versus non-sponsor rejection mix, and submit-to-rejection timing without scanning the raw request list, use `Guest Requests` or `GET /api/v1/system/guest-rejection-analytics`.

For recurring rejection snapshots without relying on a live guest analytics pull, enable scheduled guest rejection analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-rejection-analytics-exports`.

For funnel reach, submit-to-approval / invite / completion timing, and the biggest drop-off points between approval, invite delivery, and successful onboarding, use `Guest Requests` or `GET /api/v1/system/guest-conversion-analytics`.

For recurring funnel snapshots without relying on a live guest analytics pull, enable scheduled guest conversion analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-conversion-analytics-exports`.

For queued, sent, and failed invite throughput plus approval-to-invite and invite-to-completion timing without leaving the guest workflow page, use `Guest Requests` or `GET /api/v1/system/guest-invite-analytics`.

For recurring invite-throughput snapshots without relying on a live guest analytics pull, enable scheduled guest invite analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-invite-analytics-exports`.

For sponsor-by-sponsor backlog aging, slow approval response hotspots, and pending approvals that have been waiting for 30 minutes, 4 hours, or 24 hours, use `Guest Requests` or `GET /api/v1/system/guest-sponsor-analytics`.

For recurring guest delivery analytics snapshots without depending on a manual export step, enable scheduled guest delivery analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-delivery-analytics-exports`.

For top approval or invite error reasons, queued-invite age, and sponsor or company delivery hotspots, use `Guest Requests` or `GET /api/v1/system/guest-delivery-failures`.

For recurring guest delivery failure hotspot snapshots without relying on a live analytics pull during an incident, enable scheduled guest delivery failure exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-delivery-failures-exports`.

For recurring sponsor backlog and approval-response snapshots without relying on a live analytics pull, enable scheduled guest sponsor analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-sponsor-analytics-exports`.

For recurring guest lifecycle capture without depending on a manual export step, enable scheduled guest lifecycle exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-lifecycle-exports`.

For durable session and accounting history beyond the live sessions table, use `Backups` or `GET /api/v1/system/session-history`.

For started/ended trends, auth mix, role mix, VLAN mix, and peak concurrency across a selected window, use `Sessions` or `GET /api/v1/system/session-analytics`.

For recurring session/accounting capture without relying on a manual export step, enable scheduled session exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/session-exports`.

For recurring session trend snapshots without manually exporting analytics every time, enable scheduled session analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/session-analytics-exports`.

For voucher utilization, expiry pressure, and remaining-use visibility without scanning raw voucher codes by hand, use `Vouchers` or `GET /api/v1/system/voucher-analytics`.

For stale voucher inventory, unused stock backlog, and age-band pressure without manually reviewing raw voucher timestamps, use `Vouchers` or `GET /api/v1/system/voucher-aging-analytics`.

For voucher redemption behavior, first-use delay, repeat-use patterns, and voucher-session traffic without manually correlating vouchers against raw accounting rows, use `Vouchers` or `GET /api/v1/system/voucher-redemption-analytics`.

For upcoming voucher expiry pressure, unused vouchers at risk, and remaining finite-use capacity that will age out inside a selected horizon, use `Vouchers` or `GET /api/v1/system/voucher-expiry-analytics`.

For recurring voucher inventory, utilization, and expiry snapshots without relying on a manual export step, enable scheduled voucher analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/voucher-analytics-exports`.

For recurring stale voucher stock snapshots without manually exporting unused aging and trapped remaining-use data every time, enable scheduled voucher aging analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/voucher-aging-analytics-exports`.

For recurring voucher redemption behavior snapshots without manually exporting first-use delay and repeat-use trends each time, enable scheduled voucher redemption analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/voucher-redemption-analytics-exports`.

For recurring voucher expiry horizon snapshots without manually exporting at-risk unused inventory and remaining use capacity each time, enable scheduled voucher expiry analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/voucher-expiry-analytics-exports`.

For recurring HA capture without manual export timing, enable scheduled HA exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/ha/exports`.

For recurring network capture without manual export timing, enable scheduled network exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/network-exports`.

For recurring upstream AAA capture without relying on manual probe-history export timing, enable scheduled upstream AAA exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/upstream-aaa-exports`.

For recurring upgrade-readiness evidence without manually rerunning the rehearsal before every change window, enable scheduled upgrade readiness exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/upgrade-readiness-exports`.

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
- recent integration history for controller, MDM sync, and posture failures or recoveries
- external CA enrollment reachability when `ca_mode: external`

Those states are surfaced in the dashboard and reflected in alerts when delivery or sync degrades.

## Network And Vendor Observability

For edge network operations, use the dashboard or:

```text
/api/v1/system/network-observability
/api/v1/system/vendor-observability
```

Network observability combines apply history, rollback counters, DHCP lease trends, and controller sync health. Vendor observability adds per-vendor auth success and failure counters, VSA parse failures, unsupported attributes, CoA and disconnect outcomes, and a NAS compatibility score. Treat the catalog coverage matrix as the expected capability map, then use the runtime counters to spot mismatched AP profiles, unsupported vendor attributes, broken CoA behavior, or controllers that stopped accepting policy.

For controller changes, preview the operation from the dashboard or `GET /api/v1/system/controller-sync/preview`. Run `pull` first and resolve reported hash drift before a push. A push is locked until the operator enters `PUSH CONTROLLER POLICY`; its result, target adapter, hashes, drift count, applied or failed count, and controller health are written to integration history. Keep scheduled mode at `monitor` or `pull-config` until the selected controller has passed the certification lab against real hardware.

For Aruba Central, verify that `site` names the Classic Central group and `radius_profile` names an existing RADIUS server profile before the first pull. The native adapter manages only WPA2/WPA3 Enterprise WLAN objects. A warning for a personal, open, captive-portal, client-limit, isolation, portal, or bandwidth setting means that field was left untouched in Central and needs a separate controller-side workflow.

For Juniper Mist, use the regional `api.*.mist.com` endpoint and the site UUID, not the display name. Keep the API token and RADIUS shared secret in separate environment variables. Pull first to verify the site and paginated WLAN inventory; then inspect the redacted preview before push. The adapter never deletes WLANs and leaves guest portal, WxLAN policy, inventory, and non-enterprise security modes untouched.

For Ruckus SmartZone, verify API v13_1 availability, the zone UUID, and the existing authentication service name. A pull performs session login, paginated WLAN inventory, per-WLAN detail reads, and logout without mutation. Push creates only standard 802.1X WLANs and uses partial PATCH for existing WLANs. It never deletes WLANs or replaces an entire controller object.

For FortiGate, use a least-privilege REST API administrator restricted to the AegisNAS management source and the target VDOM. Verify the existing RADIUS profile before pull. The native adapter manages only FortiAP enterprise VAP objects and never sends the API token in a query parameter.

For MikroTik, use RouterOS 7.13 or newer with HTTPS REST enabled and a dedicated account. Pull first to inspect managed RADIUS and WiFi profile drift. A push never deletes records and intentionally does not assign profiles to radios or create CAPsMAN provisioning rules. Validate bridge VLAN filtering, radio package compatibility, and provisioning on a lab router before enabling scheduled push. Rotate the RADIUS shared secret through a controlled RouterOS procedure because masked secrets cannot be compared reliably through REST.

For UniFi, generate a scoped API key from the console or Site Manager and point `endpoint` at the official Network integration API base. Use the API site ID, not the legacy site name. Create the RADIUS profile and VLAN networks in UniFi before pull. Push performs full-object updates only after reading current detail, preserving unmanaged optional fields; it never deletes broadcasts, profiles, or networks. Keep scheduled mode read-only until the exact Network release and AP firmware pass the certification lab.

For Cisco Meraki, use `https://api.meraki.com/api/v1` and a least-privilege Dashboard API key with network wireless SSID read/write access. Set `site` to the network ID and create each target SSID name in an available Dashboard slot before pull. Push updates only exact same-name slots and never allocates or renames a slot. Because Dashboard reads omit RADIUS secrets, every confirmed push refreshes the configured secret on matched SSIDs; inspect the redacted preview and archive integration history before rotating it. Keep scheduled mode at `monitor` until the target MR firmware and WPA/VLAN behavior pass the certification lab.

For TIP OpenWiFi, point `endpoint` at the OWGW `/api/v1` base and use a scoped Gateway API key. Set `site` to an AP serial number or venue UUID. Pull first and resolve every missing, ambiguous, invalid-configuration, and VLAN-placement drift item. Push queues whole uCentral documents, but the adapter performs read-modify-write and changes only managed fields inside existing same-name enterprise SSIDs. It never creates an SSID, moves one between interfaces, changes interface VLANs, or overwrites unmanaged radio and service settings. Confirm command completion and convergence with `scripts/openwifi-controller-smoke-test.sh` before enabling scheduled push.

Run `scripts/vendor-certification-lab.sh` for each supported production vendor and archive its `summary.json`, API payloads, RADIUS results, packet capture, controller evidence, and optional upgrade/rollback artifacts. The full procedure and safety gates are in [vendor-certification-lab.md](vendor-certification-lab.md).

## Backup And Restore

Use the CLI for full appliance backup and the admin UI for config-only JSON backup. See [Backup and Restore Procedures](backup-restore.md).

Run at least one restore drill before production sign-off.

Before handing an issue to another team or opening a support case, download:

- the diagnostics report in JSON or CSV
- the audit history export in JSON or CSV when the issue crosses multiple operator actions
- the integration history export in JSON or CSV when the issue is controller- or MDM-related
- the support bundle zip

That gives you a quick human-readable snapshot plus the deeper redacted artifact set.

## Software Updates

Snaps refresh automatically by default. For controlled maintenance windows:

```bash
snap set system refresh.timer=sun,02:00-04:00
```

For VM or package-based deployments from a local clone, pull the updated repo and follow the relevant runbook for rebuild, reinstall, and service restart.

For in-place Ubuntu VM upgrades with migration and network safety checks, use:

```bash
sudo bash scripts/ubuntu-vm-upgrade-smoke-test.sh --wan <wan-if> --lan <lan-if>
```

For version-aware rollback rehearsal before a production change window, use:

```bash
sudo bash scripts/ubuntu-upgrade-rollback-rehearsal.sh
```

Before updating production devices:

1. Export a config JSON backup.
2. Create a full CLI backup.
3. Confirm the management path is reachable.
4. Confirm break-glass admin token access still works before changing SSO settings.
5. Apply the update.
6. Check health, sessions, RADIUS auth, portal login, onboarding, alerts, and dashboard integration state.
7. Review edge-network preview, risk banner, validation result, rollback snapshots, lease history, and apply history if network settings are part of the change.
8. For HA-enabled nodes, run `scripts/ha-active-standby-smoke-test.sh` on both active and standby nodes and review HA history plus replication freshness before failover drills.
9. If standby auto-stage or auto-activation is enabled, confirm the smoke helper summary includes the expected `auto_stage_status` and `auto_activate_status`.
10. Use `scripts/ha-failover-drill.sh` on the active node for a controlled promotion and recovery test with saved artifacts under `/var/tmp/aegisnas-ha-failover/`.
11. When you want confidence over repeated cycles instead of a single drill, run `scripts/ha-soak-test.sh --cycles <n>` on the active node. Multi-cycle runs require `high_availability.preempt: true`.
12. After both HA nodes are upgraded, run `scripts/ha-pair-upgrade-validate.sh` from the active node. Add `--peer-ssh <user@host>` when you want peer schema and service proof, not just peer API status.
13. Create and inspect a fresh upgrade rollback package, then run `scripts/ubuntu-upgrade-rollback-rehearsal.sh` so the rollback path is proven before the real maintenance window.
## Product PEN Operations

Treat a PEN change as a maintenance-window operation. Take a backup, verify HA health, use the Vendor Compatibility preview, update every peer dictionary, apply, verify `/api/v1/system/vendor-identity`, run `freeradius -XC`, and inspect a packet capture. `applying` means an interrupted operation and requires rollback recovery. Never clear migration records manually or extend `legacy_accept_until` without a documented peer dependency. Full procedure: `vendor-identity.md`.

## Attribute Registry Operations

Run `make test-attribute-registry`, `make test-dictionary-release-profiles`, `make test-compatibility-evidence`, `make test-vsa-codec`, and `make test-opaque-passthrough` before packaging or upgrading. Compare `/api/v1/system/dictionary-release-profiles`, `/api/v1/system/compatibility-evidence`, `/api/v1/system/vsa-codec`, `/api/v1/system/opaque-passthrough`, and `/api/v1/system/attribute-registry?limit=1` source hashes across HA nodes and reject mixed hashes or release profile IDs. Upstream dictionary changes require a reviewed generated diff; installed dictionary paths may be scanned for deployment coverage but cannot mutate the embedded packet registry. Full procedure: `attribute-registry.md`, `dictionary-release-profiles.md`, `compatibility-evidence.md`, `vsa-codec.md`, and `opaque-passthrough.md`.
