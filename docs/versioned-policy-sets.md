# Versioned Policy Sets

NAS-0030 adds immutable nested policy-set versions for authorization governance.
The live typed policy engine still understands the existing `policy_rules` table,
but approved policy-set activation now becomes the controlled path for
enterprise change management.

## What It Solves

Direct edits to live authorization rules are hard to review, explain, compare,
and roll back. Versioned policy sets provide:

- immutable policy content with content and flattened-policy hashes
- nested rule trees for global, site, tenant, device, and service policy layers
- maker-checker approval before activation
- activation events and rollback evidence
- simulation against a draft or historical version without changing live policy
- replay-based blast-radius analysis before activation
- support bundle, dashboard, production readiness, and OpenAPI evidence

## Policy Set Shape

Each version stores a single root set:

```json
{
  "schema_version": 1,
  "key": "default",
  "name": "Default Policy Set",
  "enabled": true,
  "priority": 0,
  "rules": [
    {
      "name": "employee-access",
      "priority": 100,
      "enabled": true,
      "match_conditions": {
        "all": [
          { "field": "authenticated", "op": "eq", "value": true },
          { "field": "groups", "op": "contains", "value": "employees" }
        ]
      },
      "action": "allow",
      "vlan": 30
    }
  ],
  "children": [
    {
      "key": "quarantine",
      "name": "Quarantine",
      "priority": 1000,
      "enabled": true,
      "rules": [
        {
          "name": "high-risk",
          "priority": 10,
          "enabled": true,
          "match_conditions": { "field": "risk_score", "op": "gte", "value": 90 },
          "action": "quarantine",
          "vlan": 99
        }
      ]
    }
  ]
}
```

Flattened rule names include their set path, for example
`default/quarantine/high-risk`. Child-set priority contributes to contained
rules, so broad overlays can intentionally outrank base policy.

## Lifecycle

1. Create a version from current live rules or explicit nested content.
2. Submit the draft for approval.
3. A different administrator approves when maker-checker is enabled.
4. A super administrator activates the approved version.
5. Activation stores a pre-change config snapshot, writes the flattened rules to
   `policy_rules`, marks the version active, supersedes the previous active
   version, records an activation event, and syncs runtime enforcement.
6. Rollback reactivates a previously approved or superseded version and records
   rollback evidence.

## APIs

```text
GET  /api/v1/system/policy-sets
GET  /api/v1/system/policy-sets/versions
POST /api/v1/system/policy-sets/versions
GET  /api/v1/system/policy-sets/versions/{id}
POST /api/v1/system/policy-sets/versions/{id}/submit
POST /api/v1/system/policy-sets/versions/{id}/approve
POST /api/v1/system/policy-sets/versions/{id}/reject
POST /api/v1/system/policy-sets/versions/{id}/activate
POST /api/v1/system/policy-sets/versions/{id}/rollback
POST /api/v1/system/policy-sets/versions/{id}/simulate
POST /api/v1/system/policy-sets/versions/{id}/analyze
GET  /api/v1/system/policy-sets/analyses
GET  /api/v1/system/policy-sets/versions/{fromID}/compare/{toID}
```

Read-only users can inspect policy-set state and persisted analyses. Ops
administrators can create, submit, simulate, and analyze versions. Super
administrators approve, reject, activate, and roll back versions.

## Configuration

```yaml
policy:
  version_approval_required: true
  version_min_approvals: 1
  version_maker_checker: true
  max_policy_set_depth: 8
  version_retention_limit: 1000
  simulation_replay_limit: 100
  simulation_retention_limit: 1000
```

Production readiness requires approval to be enabled, at least one approval,
maker-checker enabled, and an active immutable policy-set version.

## Storage

NAS-0030 adds schema v35:

- `policy_set_versions`
- `policy_set_approvals`
- `policy_set_activation_events`
- `policy_set_simulations`

NAS-0031 adds schema v36:

- `policy_engine_evaluations.request_replay_json`
- `policy_simulation_analyses`

The active policy version is unique per `set_key`. The default active key is
`default`.

## Operational Evidence

The current governance state appears in:

- `/api/v1/system/policy-sets`
- `/api/v1/system/policy-engine` under `policy_sets`
- `/api/v1/system/status` under `radius.policy_sets`
- production readiness as `policy_set_governance`
- production readiness as `policy_simulation_analysis`
- support bundles as `api/policy-sets.json`
- support bundles as `api/policy-simulation-analyses.json`
- the Policies page and Dashboard

See [policy-simulation-analysis.md](policy-simulation-analysis.md) for the
replay analysis workflow.
