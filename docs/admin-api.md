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

When scheduled audit exports are enabled, the appliance also serves:

```text
/api/v1/system/audit-exports
/api/v1/system/audit-exports/download?name=<artifact>
```

When scheduled integration exports are enabled, the appliance also serves:

```text
/api/v1/system/integration-exports
/api/v1/system/integration-exports/download?name=<artifact>
```

Use this report when you want one payload that combines:

- session and alert counts
- managed network apply and lease-trend stats
- HA role and failover counters
- upgrade-readiness results
- integration and runtime status snapshots
- controller, MDM sync, and posture history counters

From the admin UI:

1. sign in
2. open `Backups`
3. select `Refresh Report`
4. download `JSON` or `CSV`
5. review the scheduled export runtime and recent artifacts when recurring export is enabled

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

## Operational Reminder

The OpenAPI schema describes the live contract, but it does not replace change safety.

For risky actions like:

- network apply
- rollback restore
- HA activation

use the matching runbook as well so you keep the preview, validation, backup, and rollback steps in place.
