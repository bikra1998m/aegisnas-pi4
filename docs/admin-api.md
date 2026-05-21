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

Use this report when you want one payload that combines:

- session and alert counts
- managed network apply and lease-trend stats
- HA role and failover counters
- upgrade-readiness results
- integration and runtime status snapshots

From the admin UI:

1. sign in
2. open `Backups`
3. select `Refresh Report`
4. download `JSON` or `CSV`
5. review the scheduled export runtime and recent artifacts when recurring export is enabled

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

## Operational Reminder

The OpenAPI schema describes the live contract, but it does not replace change safety.

For risky actions like:

- network apply
- rollback restore
- HA activation

use the matching runbook as well so you keep the preview, validation, backup, and rollback steps in place.
