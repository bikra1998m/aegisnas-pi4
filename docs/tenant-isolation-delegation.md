# Tenant Isolation And Delegated Policy Trees

NAS-0034 adds hard tenant ownership to delegated administration and policy-set
operations. The feature is software-complete when tenant profiles, resource
bindings, tenant-scoped policy versions, API/UI controls, readiness checks,
support-bundle evidence, and automated tests are present. Hardware and customer
environment validation are tracked separately in
`nas-0034-release-certification-checklist.md`.

## Problem Solved

Managed-service and multi-tenant enterprise deployments need each operator,
policy tree, controller scope, secret namespace, CA namespace, dictionary
profile, and billing reference to stay inside the correct tenant boundary.
Without a hard boundary, a delegated admin could accidentally view, simulate,
activate, or roll back another tenant's policy.

NAS-0034 provides:

- tenant profiles for ownership metadata and operational scope
- resource bindings for tenant-owned and shared resources
- tenant-scoped immutable policy-set versions
- scoped list/read/simulate/analyze/activate/rollback behavior
- fail-closed resource access evaluation
- audited allow, deny, monitor, and error decisions
- production-readiness and support-bundle evidence

## Standards And Vendor Scope

Tenant isolation is not a single RADIUS RFC feature. It is a product safety
layer required by MSP, controller, cloud NAC, and multi-site vendors such as
Cisco, Aruba/HPE, Juniper Mist, Ruckus, Fortinet, Meraki, UniFi, Extreme, and
Huawei. It protects the platform semantics that later vendor packs use when
mapping roles, VLANs, ACLs, bandwidth, posture, device groups, controller
objects, and accounting identities.

Applicable standards and references:

- RFC 2865 for RADIUS authorization policy context.
- RFC 2866 for accounting records that carry tenant and subscriber context.
- RFC 5176 for later CoA ownership and tenant handoff.
- Internal RBAC, audit, database, backup, and HA governance standards.

## Configuration

Tenant isolation lives under `governance`:

```yaml
governance:
  delegated_admin_enabled: true
  rbac_mode: "local"
  multi_tenant_enabled: true
  tenant_claim: "tenant"
  isolation_mode: "enforce"
  fail_closed: true
  default_tenant: ""
  max_tenants: 256
  tenant_profile_required: true
  enforce_policy_set_ownership: true
  enforce_resource_ownership: true
  resource_audit_enabled: true
  resource_retention_limit: 10000
  shared_resource_types:
    - system_status
    - production_readiness
    - support_bundle
```

`monitor` records denied decisions but allows the request. `enforce` returns a
forbidden decision for out-of-scope tenant access, missing tenant profiles,
missing resource bindings, inactive bindings, and resources owned by another
tenant.

`fail_closed` controls unexpected database or evaluation errors. Keep it true in
production.

## Data Model

Schema v39 adds:

- `tenant_profiles`: tenant key, display name, status, data residency, secret
  namespace, CA namespace, dictionary profile, quota JSON, controller scope JSON,
  billing account reference, actor, and timestamps.
- `tenant_resource_bindings`: tenant, resource type, resource ID, owner kind,
  status, evidence JSON, actor, and timestamps.
- `tenant_isolation_events`: audited allow, deny, monitor, and error decisions.

Schema v39 also adds `tenant` columns to:

- `policy_set_versions`
- `policy_set_activation_events`
- `policy_set_simulations`
- `policy_simulation_analyses`

## Policy Behavior

When multi-tenant governance is enabled and a policy request contains a tenant,
the policy engine loads the active policy set for that tenant. If no active
tenant policy exists, evaluation returns the normal default deny decision. It
does not fall back to the global policy.

Global policy versions continue to synchronize the legacy `policy_rules` table.
Tenant-owned policy versions do not overwrite global runtime rules during
activation.

Delegated admins with tenant scopes can list, read, simulate, analyze, approve,
activate, and roll back only versions inside their allowed tenant list. Break
glass and unscoped super admins retain platform-wide access.

## API

- `GET /api/v1/system/tenant-isolation`
- `POST /api/v1/system/tenant-isolation/evaluate`
- `POST /api/v1/system/tenant-isolation/tenants`
- `PUT /api/v1/system/tenant-isolation/tenants/{tenant}`
- `POST /api/v1/system/tenant-isolation/resources`

Tenant-scoped policy versions use the existing policy-set APIs with the
additional `tenant` field on create, read, list, simulation, analysis,
activation, rollback, and events.

## Operations

1. Enable delegated administration and multi-tenant governance.
2. Create active tenant profiles for every managed tenant.
3. Bind tenant-owned policy sets, controller scopes, secret namespaces, CA
   namespaces, dictionary profiles, NAS clients, certificate templates, and
   billing accounts.
4. Run `/api/v1/system/tenant-isolation/evaluate` for representative resources
   in monitor mode.
5. Review `tenant_isolation_events` and support-bundle evidence.
6. Switch `governance.isolation_mode` to `enforce`.
7. Create and activate tenant-owned policy versions.

## Monitoring

Tenant isolation appears in:

- `/api/v1/system/status` under `radius.tenant_isolation`
- `/api/v1/system/production-readiness` as `tenant_isolation`
- support bundles at `api/tenant-isolation.json`
- Access Settings under Admin Identity And Governance

Track active tenant count, owned resource count, tenant policy scope count,
denied decisions, monitor decisions, and recent errors.

## HA And Backup

Tenant profiles, resource bindings, isolation events, and tenant policy versions
are ordinary database state. They are included in PostgreSQL/SQLite backups,
support bundles, HA replication packages, and schema migration rehearsals.
External HA validation remains in the release certification checklist.
