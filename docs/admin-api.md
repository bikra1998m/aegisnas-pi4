# Admin API Guide

This guide is the operator and integration entry point for the AegisNAS admin API.

Use it when you want to:

- inspect the live API contract
- understand bearer-auth expectations
- understand which admin roles can call which endpoint families
- point external tools at a stable OpenAPI document

Use this guide together with:

- [Operations Guide](operations.md)
- [Upgrade Rollback Runbook](upgrade-rollback-runbook.md)
- [HA Active/Standby Runbook](ha-active-standby-runbook.md)

## OpenAPI Endpoint

The appliance now serves a live OpenAPI document at:

```text
/api/v1/openapi.json
```

Examples:

```bash
curl -fsS http://127.0.0.1:8083/api/v1/openapi.json | jq '.info, .servers'
```

Or from the admin UI:

1. sign in
2. open `Backups`
3. select `Download OpenAPI JSON`

## Deployment Scaling Status

System status and draft settings evaluation include the deployment profile, hardware hints, capability states, and automatic scaling plan:

```text
/api/v1/system/status
/api/v1/system/settings/evaluate
```

The `deployment.scaling` object reports the effective Lite, Branch, or Enterprise hardware mode, whether the selected profile fits the declared hardware, recommended retention and limits, and active gating actions. Use it before enabling heavyweight features on low-spec hardware.

## Production Readiness Endpoint

Before production sign-off, run the deployment readiness report:

```text
/api/v1/system/production-readiness
```

Example:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/production-readiness | jq '.status, .checks[] | select(.status != "passed")'
```

The report checks config validation, declared hardware scaling, AegisNAS vendor identity and placeholder PEN use, product dictionary detection, active vendor compatibility packs, deployed NAS profile coverage, active feature gates, controller readiness, and vendor runtime evidence from live RADIUS/CoA counters. A short summary also appears in `/api/v1/system/status` as `production_readiness`.

## Vendor Compatibility Endpoint

The appliance exposes the built-in AegisNAS vendor dictionary catalog and semantic registry at:

```text
/api/v1/system/vendor-compatibility
```

Examples:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-compatibility | jq '.summary'
```

Use this endpoint when you want to confirm:

- the active AegisNAS product vendor ID and built-in VSA count
- whether the product vendor ID still uses the lab placeholder and where `dictionary.aegisnas` should be installed
- the active vendor compatibility packs from `radius.vendor.compatibility_packs`
- the parsed dictionary coverage matrix through `dictionary_coverage`, including configured or auto-detected FreeRADIUS dictionary imports
- the same coverage model is available from `aegis-admin scan-radius-dictionaries` for offline JSON/CSV scans of FreeRADIUS dictionary trees
- reply preview responses include normalized ACL intent plus per-pack ACL exports for Cisco AVPair, Aruba/NAS filter rules, AegisNAS ACL rules, and profile-style vendor hints
- the deployed RADIUS client `nas_type` values and their effective reply packs through `client_profiles`
- the current profile coverage, unknown profile list, and fallback count through `profile_summary`
- which semantic policy keys already have product attributes
- which vendor-compatibility areas are implemented versus planned
- which pieces are intended for lite, branch, or enterprise appliances

The API also provides a non-mutating reply preview endpoint:

```text
/api/v1/system/vendor-reply-preview
```

Example:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"nas_type":"aruba","role":"guest","vlan":20,"download_kbps":50000,"upload_kbps":20000}' \
  http://127.0.0.1:8083/api/v1/system/vendor-reply-preview | jq '.effective_packs, .attributes'
```

Use this before introducing a new AP, switch, or controller profile so you can verify the exact reply attributes and fallback warnings without changing live policy.

## ACL Policy Library

Vendor-neutral dynamic ACL policies use the standard staged configuration workflow:

```text
GET    /api/v1/acl-policies
POST   /api/v1/acl-policies
PUT    /api/v1/acl-policies/{id}
DELETE /api/v1/acl-policies/{id}
POST   /api/v1/validate
POST   /api/v1/apply
```

Each policy stores a stable name, optional vendor inbound/outbound ACL names, and up to 64 normalized rules. ACL policy changes are included in config revision snapshots and rollback. A vendor reply preview containing only `acl_policy_name` loads an enabled applied policy and reports `acl_policy_loaded: true`; explicit `acl_rules` remain available for one-off previews.

Roles and policy rules may assign an enabled library entry with `acl_policy_name`. Validation rejects missing or disabled references, and deletion is blocked while a role or policy rule still uses the ACL. Portal policy evaluation and CoA persist the selected name on the active session. Local FreeRADIUS users receive the role's standard and configured vendor ACL attributes when the generated `users` file is applied.

After committing a role, user, or ACL binding through `/api/v1/apply`, run `POST /api/v1/system/radius-apply` (the **Apply RADIUS Config** action in Access Settings). This regenerates the local-user entries in `mods-config/files/authorize` and the legacy `users` path, validates the complete FreeRADIUS configuration, and restarts FreeRADIUS. Database-backed portal decisions and CoA updates do not require this regeneration. Local bcrypt credentials support PAP and EAP-TTLS/PAP; CHAP and PEAP-MSCHAPv2 require a compatible cleartext or NT password verifier, while EAP-TLS uses certificates.

## Vendor Observability Endpoint

Runtime vendor compatibility evidence is available at:

```text
/api/v1/system/vendor-observability
/api/v1/system/vendor-observability/export?format=csv
/api/v1/system/vendor-observability/export?format=json
```

Example:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-observability | jq '.summary'
```

Use the catalog and reply preview endpoints to confirm what AegisNAS intends to support. Use vendor observability to confirm what the live RADIUS and dynamic-authorization paths are seeing: auth success and failure counts, parsed VSAs, VSA parse failures, unsupported attributes, CoA and disconnect outcomes, last event message, and the computed NAS compatibility score per vendor and NAS type.

The same summary is included in `/api/v1/system/status` under `radius.vendor_observability` and in `/api/v1/system/network-observability` under `vendor_observability`, so dashboards and support bundles can show static coverage next to runtime failures.

## Controller Adapter Catalog

Controller-native integration readiness is available at:

```text
/api/v1/system/controller-adapters
```

The response lists the supported controller adapters, whether each adapter is native or contract-based, the selected platform's capabilities, required site or network identifier, credential environment readiness, runtime sync status, and setup warnings. Cisco and Ruckus readiness check `api_username_env` and `api_password_env`; token-based adapters check `api_token_env`. Aruba and FortiGate use `radius_profile` as an existing controller RADIUS profile; Ruckus uses it as the existing SmartZone authentication service name. Mist enterprise WLAN readiness requires `radius_server`, `radius_secret_env`, and the named secret in the process environment.

Controller policy operations are available at:

```text
GET  /api/v1/system/controller-sync/preview?operation=pull
GET  /api/v1/system/controller-sync/preview?operation=push
POST /api/v1/system/controller-sync
```

`pull` performs a read-only state request and compares observed controller resources with AegisNAS desired state. `push` requires `confirmation` to equal `PUSH CONTROLLER POLICY`. The Cisco native adapter reconciles ERS downloadable ACL and authorization profile resources with lookup-before-create/update behavior. The Aruba Central Classic native adapter reconciles enterprise WLAN resources through `/configuration/v2/wlan/{group}/{wlan}` and references a pre-existing Central RADIUS profile. The Juniper Mist native adapter pages through `/api/v1/sites/{site_id}/wlans` and creates or updates WPA2/WPA3 Enterprise WLANs by SSID. The Ruckus native adapter uses SmartZone v13_1 sessions and zone-scoped standard 802.1X WLAN resources. The FortiGate native adapter reconciles VDOM-scoped FortiAP VAP objects through the FortiOS CMDB API. MikroTik and UniFi use their declared AegisNAS contract endpoints. Manual operations update `controller_automation` runtime counters and durable integration history.

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/controller-sync/preview?operation=pull' | jq '.preview'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"operation":"pull"}' \
  http://127.0.0.1:8083/api/v1/system/controller-sync | jq '.status, .result'
```

Configured `monitor` and `pull-config` modes use the read-only pull path in the background scheduler. Treat a vendor adapter as production-authoritative only after its endpoint contract, returned hashes, and policy enforcement have passed the hardware certification runbook.

## Support Bundle Endpoints

The appliance also serves support bundle preview and live bundle download at:

```text
/api/v1/system/support-bundle/summary
/api/v1/system/support-bundle
```

Use these when you want a redacted ZIP with runtime status, history, diagnostics, OpenAPI, and upgrade context in one operator bundle.

## Diagnostics Report Endpoints

The appliance also serves a cross-domain diagnostics snapshot at:

```text
/api/v1/system/diagnostics-report
```

And export variants at:

```text
/api/v1/system/diagnostics-report/export?format=json
/api/v1/system/diagnostics-report/export?format=csv
```

When scheduled diagnostics exports are enabled, the appliance also serves:

```text
/api/v1/system/diagnostics-exports
/api/v1/system/diagnostics-exports/download?name=<artifact>
```

When scheduled support bundle exports are enabled, the appliance also serves:

```text
/api/v1/system/support-bundle-exports
/api/v1/system/support-bundle-exports/download?name=<artifact>
```

When scheduled audit exports are enabled, the appliance also serves:

```text
/api/v1/system/audit-exports
/api/v1/system/audit-exports/download?name=<artifact>
```

When scheduled session exports are enabled, the appliance also serves:

```text
/api/v1/system/session-exports
/api/v1/system/session-exports/download?name=<artifact>
```

When scheduled session analytics exports are enabled, the appliance also serves:

```text
/api/v1/system/session-analytics-exports
/api/v1/system/session-analytics-exports/download?name=<artifact>
```

When scheduled voucher analytics exports are enabled, the appliance also serves:

```text
/api/v1/system/voucher-analytics-exports
/api/v1/system/voucher-analytics-exports/download?name=<artifact>
```

When scheduled voucher aging analytics exports are enabled, the appliance also serves:

```text
/api/v1/system/voucher-aging-analytics-exports
/api/v1/system/voucher-aging-analytics-exports/download?name=<artifact>
```

When scheduled voucher redemption analytics exports are enabled, the appliance also serves:

```text
/api/v1/system/voucher-redemption-analytics-exports
/api/v1/system/voucher-redemption-analytics-exports/download?name=<artifact>
```

When scheduled voucher expiry analytics exports are enabled, the appliance also serves:

```text
/api/v1/system/voucher-expiry-analytics-exports
/api/v1/system/voucher-expiry-analytics-exports/download?name=<artifact>
```

When scheduled integration exports are enabled, the appliance also serves:

```text
/api/v1/system/integration-exports
/api/v1/system/integration-exports/download?name=<artifact>
```

When scheduled HA exports are enabled, the appliance also serves:

```text
/api/v1/system/ha/exports
/api/v1/system/ha/exports/download?name=<artifact>
```

When scheduled network exports are enabled, the appliance also serves:

```text
/api/v1/system/network-exports
/api/v1/system/network-exports/download?name=<artifact>
```

When scheduled upstream AAA exports are enabled, the appliance also serves:

```text
/api/v1/system/upstream-aaa-exports
/api/v1/system/upstream-aaa-exports/download?name=<artifact>
```

When scheduled upgrade readiness exports are enabled, the appliance also serves:

```text
/api/v1/system/upgrade-readiness-exports
/api/v1/system/upgrade-readiness-exports/download?name=<artifact>
```

Use this report when you want one payload that combines:

- session and alert counts
- guest lifecycle and delivery state
- managed network apply and lease-trend stats
- HA role and failover counters
- upgrade-readiness results
- integration and runtime status snapshots
- controller, MDM sync, posture, and upstream AAA history counters

## Guest Lifecycle Endpoints

The appliance also serves a guest access lifecycle report at:

```text
/api/v1/system/guest-lifecycle
```

And export variants at:

```text
/api/v1/system/guest-lifecycle/export?format=json
/api/v1/system/guest-lifecycle/export?format=csv
/api/v1/system/guest-delivery-analytics
/api/v1/system/guest-delivery-analytics/export?format=json
/api/v1/system/guest-delivery-analytics/export?format=csv
/api/v1/system/guest-rejection-analytics
/api/v1/system/guest-rejection-analytics/export?format=json
/api/v1/system/guest-rejection-analytics/export?format=csv
/api/v1/system/guest-rejection-analytics-exports
/api/v1/system/guest-rejection-analytics-exports/download?name=<artifact>
/api/v1/system/guest-conversion-analytics
/api/v1/system/guest-conversion-analytics/export?format=json
/api/v1/system/guest-conversion-analytics/export?format=csv
/api/v1/system/guest-conversion-analytics-exports
/api/v1/system/guest-conversion-analytics-exports/download?name=<artifact>
/api/v1/system/guest-invite-analytics
/api/v1/system/guest-invite-analytics/export?format=json
/api/v1/system/guest-invite-analytics/export?format=csv
/api/v1/system/guest-invite-analytics-exports
/api/v1/system/guest-invite-analytics-exports/download?name=<artifact>
/api/v1/system/guest-delivery-failures
/api/v1/system/guest-delivery-failures/export?format=json
/api/v1/system/guest-delivery-failures/export?format=csv
/api/v1/system/guest-delivery-failures-exports
/api/v1/system/guest-delivery-failures-exports/download?name=<artifact>
/api/v1/system/guest-sponsor-analytics
/api/v1/system/guest-sponsor-analytics/export?format=json
/api/v1/system/guest-sponsor-analytics/export?format=csv
/api/v1/system/guest-delivery-analytics-exports
/api/v1/system/guest-delivery-analytics-exports/download?name=<artifact>
/api/v1/system/guest-sponsor-analytics-exports
/api/v1/system/guest-sponsor-analytics-exports/download?name=<artifact>
/api/v1/system/guest-lifecycle-exports
/api/v1/system/guest-lifecycle-exports/download?name=<artifact>
```

Use the delivery analytics endpoints when you want the sponsor-approval backlog, approval and invite delivery failure mix, top sponsors, and approval-to-completion timing without exporting the full registration history.

Use the rejection analytics endpoints when you want the top rejection reasons, sponsor versus non-sponsor rejection mix, after-approval reversals, and submit-to-rejection timing without scanning the raw request table by hand. Enable the scheduled rejection export path when you want recurring snapshots in `Backups` without depending on a live guest analytics pull.

Use the guest conversion analytics endpoints when you want funnel reach, submit-to-approval / invite / completion timing, and the main drop-off points between approval, invite delivery, and successful completion.

Use the invite analytics endpoints when you want queued, sent, and failed invite throughput, approval-to-invite timing, and completion-after-invite movement without paging through the raw guest request table.

Use the scheduled invite analytics export endpoints when you want that invite-throughput and completion view written to disk on a timer for operator handoff or post-incident review.

Use the delivery failure endpoints when you want top approval or invite error reasons, queued-invite age, and sponsor or company hotspots without paging through the raw registration table.

Use the scheduled delivery failure export endpoints when you want those hotspots saved to disk on a timer for later review or incident handoff.

Use the sponsor analytics endpoints when you want aging sponsor backlog, slow-response hotspots, sponsor-by-sponsor pending queues, and approval timing without leaving the guest operations workflow.

Optional query parameters:

- `status=pending|approved|rejected|completed`
- `limit=<n>`
- `window_hours=<n>`
- `bucket_count=<n>`

Use this report when you want:

- pending, approved, rejected, and completed guest-request counts in one place
- approval and invite delivery failure visibility without scanning raw rows by hand
- recent submitted/approved/rejected/completed trends for the guest workflow window
- handoff-ready JSON or CSV exports from the same guest workflow page operators already use
- recurring JSON or CSV artifacts that land on disk without waiting for a manual export click

From the admin UI:

1. sign in
2. open `Guest Requests`
3. filter by status when you want a narrower lifecycle view
4. review the summary and recent lifecycle trend
5. export `JSON` or `CSV` when you need an operator handoff artifact

## Session History Endpoints

The appliance also keeps durable session and accounting history at:

```text
/api/v1/system/session-history
```

And export variants at:

```text
/api/v1/system/session-history/export?format=json
/api/v1/system/session-history/export?format=csv
```

Optional query parameters:

- `username=<exact-username>`
- `auth_method=<exact-method>`
- `active=true|false`
- `limit=<n>`

Use this history when you want:

- a durable view of who authenticated, how, and when the session ended
- accounting-oriented byte and duration exports for operator handoff
- recurring session artifacts without relying on a manual export step

For summarized session activity trends, the appliance also serves:

```text
/api/v1/system/session-analytics
/api/v1/system/session-analytics/export?format=json
/api/v1/system/session-analytics/export?format=csv
```

Optional query parameters:

- `username=<exact-username>`
- `auth_method=<exact-method>`
- `window_hours=<n>`
- `bucket_count=<n>`

Use this analytics view when you want:

- started vs ended session trends over the selected window
- peak concurrent session counts without scanning raw rows by hand
- auth-method, role, and VLAN mix snapshots for operator review
- ended-session traffic and duration summaries that are safer to reason about than cumulative active-session bytes

## Voucher Analytics Endpoints

The appliance also serves voucher inventory and usage analytics at:

```text
/api/v1/system/voucher-analytics
/api/v1/system/voucher-analytics/export?format=json
/api/v1/system/voucher-analytics/export?format=csv
/api/v1/system/voucher-aging-analytics
/api/v1/system/voucher-aging-analytics/export?format=json
/api/v1/system/voucher-aging-analytics/export?format=csv
/api/v1/system/voucher-redemption-analytics
/api/v1/system/voucher-redemption-analytics/export?format=json
/api/v1/system/voucher-redemption-analytics/export?format=csv
/api/v1/system/voucher-expiry-analytics
/api/v1/system/voucher-expiry-analytics/export?format=json
/api/v1/system/voucher-expiry-analytics/export?format=csv
/api/v1/system/voucher-expiry-analytics-exports
/api/v1/system/voucher-expiry-analytics-exports/download?name=<artifact>
/api/v1/system/voucher-analytics-exports
/api/v1/system/voucher-analytics-exports/download?name=<artifact>
/api/v1/system/voucher-aging-analytics-exports
/api/v1/system/voucher-aging-analytics-exports/download?name=<artifact>
```

Optional query parameters:

- `window_hours=<n>`
- `bucket_count=<n>`

Use this analytics view when you want:

- active, exhausted, expired, and unused voucher counts in one place
- remaining-use and utilization snapshots without scanning raw codes by hand
- role mix and voucher-state mix for operator review
- bucketed voucher creation and expiry pressure trends from the same page where operators create vouchers
- recurring JSON or CSV voucher analytics artifacts without waiting for a manual export click

Use the voucher redemption analytics endpoints when you want:

- a clear view of how many current vouchers were actually redeemed
- first-use delay from voucher creation to real session start
- repeat-use versus one-time-use behavior across the current voucher set
- bucketed voucher session starts, first redemptions, and completed-session traffic without pivoting over raw accounting rows

Use the voucher expiry analytics endpoints when you want:

- a forward-looking view of vouchers expiring inside the selected horizon
- unused vouchers that are about to expire without ever being redeemed
- remaining finite-use capacity that will age out with upcoming expirations
- role hotspots for expiring inventory and unused at-risk vouchers
- bucketed upcoming expiry pressure instead of only historical voucher creation counts

From the admin UI:

1. sign in
2. open `Vouchers`
3. review the inventory summary, role mix, and state mix
4. review the expiry horizon when you need upcoming expiration pressure and unused-at-risk visibility
5. review the redemption summary and trend when you need first-use and reuse behavior
6. export `JSON` or `CSV` when you need a handoff-ready snapshot
7. review scheduled voucher analytics export runtime and artifacts when recurring export is enabled

From the admin UI:

1. sign in
2. open `Sessions` for live activity and trend analytics
3. open `Backups` for durable `Session History`
4. export `JSON` or `CSV`
5. review scheduled session export runtime and artifacts when recurring export is enabled
6. review scheduled session analytics export runtime and artifacts when recurring analytics capture is enabled

## Upstream AAA History Endpoints

The appliance also keeps durable upstream AAA probe history at:

```text
/api/v1/system/upstream-aaa-history
```

And export variants at:

```text
/api/v1/system/upstream-aaa-history/export?format=json
/api/v1/system/upstream-aaa-history/export?format=csv
```

Optional query parameters:

- `server=<home-server-name>`
- `status=ok|degraded|down|disabled`
- `limit=<n>`

Use this history when you want:

- a durable timeline for upstream RADIUS probe health
- exportable evidence for fail-over, reject, and timeout investigation
- a way to compare live dashboard state with recent probe outcomes

From the admin UI:

1. sign in
2. open `Backups`
3. review `Upstream AAA History`
4. export `JSON` or `CSV` when you need a handoff-ready timeline
5. review scheduled upstream AAA export runtime and artifacts when recurring export is enabled

From the admin UI:

1. sign in
2. open `Backups`
3. select `Refresh Report`
4. download `JSON` or `CSV`
5. review the scheduled export runtime and recent artifacts when recurring export is enabled

## Upgrade Readiness Export Endpoints

The appliance also serves live upgrade readiness at:

```text
/api/v1/system/upgrade-readiness
```

When recurring upgrade readiness export is enabled, operators can also use:

```text
/api/v1/system/upgrade-readiness-exports
/api/v1/system/upgrade-readiness-exports/download?name=<artifact>
```

Use these when you want:

- durable migration-rehearsal evidence for a maintenance window
- a saved trail of config validation and schema checks
- recurring readiness snapshots without manually rerunning the report

From the admin UI:

1. sign in
2. open `Backups`
3. review `Upgrade Readiness`
4. review the scheduled upgrade readiness export runtime and artifacts when recurring export is enabled

## Integration History Endpoints

The appliance also keeps durable automation history for controller sync, MDM sync, and posture evaluation at:

```text
/api/v1/system/integration-history
```

And export variants at:

```text
/api/v1/system/integration-history/export?format=json
/api/v1/system/integration-history/export?format=csv
```

Optional query parameters:

- `component=controller_automation`
- `component=mdm_sync`
- `component=posture_checks`
- `limit=<n>`

Use this history when you want:

- more than the last runtime status message
- a quick operator timeline for sync failures and recoveries
- exportable evidence for controller or MDM troubleshooting
- recurring integration artifacts without relying on manual export timing

Controller history details can include adapter name, request URL, desired-state hash, observed-state hash, drift flag and count, applied and failed item counts, controller health, compatibility score, and response warnings. These fields also flow into network observability so operators can see whether a controller accepted the latest AegisNAS policy or reported drift.

From the admin UI:

1. sign in
2. open `Backups`
3. review `Integration History`
4. export `JSON` or `CSV` when you need to hand it to another team
5. review scheduled integration export runtime and artifacts when recurring export is enabled

## HA History Endpoints

The appliance also keeps durable HA history at:

```text
/api/v1/system/ha/history
```

And export variants at:

```text
/api/v1/system/ha/history/export?format=json
/api/v1/system/ha/history/export?format=csv
```

When recurring HA export is enabled, operators can also use:

```text
/api/v1/system/ha/exports
/api/v1/system/ha/exports/download?name=<artifact>
```

Use this history when you want:

- a failover and replication timeline beyond the latest runtime message
- exportable evidence for HA drills and incident review
- recurring HA artifacts without relying on manual export timing

From the admin UI:

1. sign in
2. open `Backups`
3. review `HA History`
4. export `JSON` or `CSV`
5. review scheduled HA export runtime and artifacts when recurring export is enabled

## Network History Endpoints

The appliance also keeps durable managed network and DHCP lease history at:

```text
/api/v1/system/network-apply-history
/api/v1/system/dhcp-lease-history
```

And export variants at:

```text
/api/v1/system/network-apply-history/export?format=json
/api/v1/system/network-apply-history/export?format=csv
/api/v1/system/dhcp-lease-history/export?format=json
/api/v1/system/dhcp-lease-history/export?format=csv
```

When recurring network export is enabled, operators can also use:

```text
/api/v1/system/network-exports
/api/v1/system/network-exports/download?name=<artifact>
```

Use this history when you want:

- a durable apply and rollback timeline beyond the latest validation toast
- recurring DHCP lease evidence for client troubleshooting
- exportable network change artifacts without relying on a manual export step

When passive profiling is enabled, DHCP observations also update device inventory with hostname, DHCP client ID, MAC OUI, profile risk score, and risk reasons. If posture remediation is enabled, high-risk active sessions can be marked with `quarantine-profile-risk`.

Operators and trusted collectors can also submit richer profile observations at:

```text
/api/v1/devices/profile-observations
```

The request can include MAC, IP, username, session ID, user-agent, hostname, DHCP fingerprint, LLDP chassis or port, and CDP device or port fields. AegisNAS stores those signals on the device inventory record, updates profile risk reasons, and can quarantine high-risk active sessions when posture remediation is enabled.

Device certificate lifecycle operations are available at:

```text
/api/v1/devices/certificates
/api/v1/devices/certificates/{id}/status
/api/v1/devices/certificates/{id}/revoke
/api/v1/devices/certificates/{id}/renew
/api/v1/devices/certificates/crl
```

Use these to inspect active, expired, and revoked certificates, revoke lost-device certificates, renew a device certificate, and download an internal-CA CRL. Revoke and renew require an ops or super admin session.

From the admin UI:

1. sign in
2. open `Access Settings` to review live network history
3. open `Backups`
4. review scheduled network export runtime and artifacts when recurring export is enabled

## Audit History Endpoints

The appliance also serves a durable audit timeline at:

```text
/api/v1/system/audit-history
```

And export variants at:

```text
/api/v1/system/audit-history/export?format=json
/api/v1/system/audit-history/export?format=csv
```

Optional query parameters:

- `user=<admin-subject>`
- `action_prefix=download_`
- `action_prefix=guest_`
- `limit=<n>`

Use this history when you want:

- a quick record of admin-visible actions
- change-window evidence for network, HA, or upgrade work
- an exportable operator timeline for incident review
- recurring audit artifacts without relying on a manual export step

From the admin UI:

1. sign in
2. open `Backups`
3. review `Audit History`
4. export `JSON` or `CSV` when you need a handoff-ready timeline
5. review scheduled audit export runtime and artifacts when recurring export is enabled

## What The Schema Includes

The OpenAPI document includes:

- public auth and documentation endpoints
- authenticated admin endpoints
- bearer-auth security scheme
- grouped tags for system, network, HA, upgrade, guest, and AAA paths
- AegisNAS-specific role hints through `x-aegisnas-roles`
- visibility hints through `x-aegisnas-visibility`

That means integrations can see both:

- the path and method shape
- the likely operator role needed to call it

## Authentication Expectations

Most admin endpoints require:

```text
Authorization: Bearer <token>
```

The schema advertises this as `bearerAuth`.

The common flow is:

1. use `GET /api/v1/auth/options`
2. sign in through token or admin SSO
3. call the protected endpoint with the bearer token

## Role Hints

The OpenAPI document includes `x-aegisnas-roles` for authenticated operations.

Common values are:

- `read_only`
- `guest_admin`
- `ops_admin`
- `super_admin`

Treat these as operational hints that match the current appliance authorization model.

## Good Uses For The Schema

Use the OpenAPI JSON for:

- internal tooling
- support automation
- API client generation experiments
- runbook authoring
- change-review prep before automation is pointed at the appliance
- mapping diagnostics-report exports into external support workflows
- mapping integration-history exports into controller and endpoint support workflows
- mapping scheduled integration exports into controller, MDM, and posture support handoffs
- mapping scheduled audit exports into change-review and incident timelines
- mapping scheduled HA exports into failover drill evidence and recovery handoffs
- mapping scheduled upstream AAA exports into RADIUS fail-over and timeout investigations
- mapping scheduled session analytics exports into recurring access-pattern and concurrency reviews
- mapping vendor-compatibility reports into packet simulation, support, and controller-pack planning

## Operational Reminder

The OpenAPI schema describes the live contract, but it does not replace change safety.

For risky actions like:

- network apply
- rollback restore
- HA activation

use the matching runbook as well so you keep the preview, validation, backup, and rollback steps in place.
