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

Use the rejection analytics endpoints when you want the top rejection reasons, sponsor versus non-sponsor rejection mix, after-approval reversals, and submit-to-rejection timing without scanning the raw request table by hand.

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

## Operational Reminder

The OpenAPI schema describes the live contract, but it does not replace change safety.

For risky actions like:

- network apply
- rollback restore
- HA activation

use the matching runbook as well so you keep the preview, validation, backup, and rollback steps in place.
