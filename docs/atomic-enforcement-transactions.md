# Atomic Enforcement Transactions And Drift Rollback

NAS-0058 makes local and controller enforcement changes run through one
evidence-backed transaction coordinator. VLAN lifecycle, QoS scheduler,
subscriber route export, runtime firewall, and controller sync participants
are previewed in dependency order, applied as one operation, checked for drift,
and compensated in reverse order when a later participant fails.

## Scope

Implemented software scope:

- Atomic enforcement planner with schema version `1`.
- Ordered targets: `vlan_lifecycle`, `subscriber_route_export`,
  `runtime_qos`, `runtime_firewall`, and `controller_sync`.
- Fail-closed preflight for blocked participants.
- First-apply support when targets have no active snapshot yet.
- Reverse-order compensation for participants that publish rollback snapshots.
- Optional post-apply drift detection and optional rollback on drift.
- Durable transaction ledger in `enforcement_transactions`.
- Durable per-target step ledger in `enforcement_transaction_steps`.
- Durable drift evidence in `enforcement_drift_events`.
- Configurable participant list, timeouts, drift tolerance, and retention.
- Admin API, OpenAPI, RBAC, production readiness, support bundle, system
  status, Access Settings, and Dashboard visibility.

External controller behavior, physical nftables/tc/ip/hostapd mutation, vendor
hardware, FreeRADIUS lab captures, HA drills, performance, soak, security
review, production deployment, and customer validation are tracked in
`nas-0058-release-certification-checklist.md` and do not block engineering
completion.

## Transaction Model

The coordinator builds a preview for each configured target, sorts targets into
the dependency order below, and records a deterministic plan fingerprint:

1. `vlan_lifecycle`
2. `subscriber_route_export`
3. `runtime_qos`
4. `runtime_firewall`
5. `controller_sync`

`blocked` targets stop apply when `fail_closed` is enabled. `degraded` targets
can still apply; this is expected during first deployment when no active
snapshots exist yet. `skipped` targets are recorded but not applied.

If a target apply fails, already-applied targets with `previous_snapshot_id`
are rolled back in reverse order. Compensation steps are stored in the same
transaction ledger with `operation=compensate`.

## Drift

Drift detection compares each target's desired fingerprint with the active
fingerprint exposed by that target:

- Runtime firewall: active `runtime_firewall_snapshots.ruleset_fingerprint`.
- Runtime QoS: active `runtime_qos_snapshots.plan_fingerprint`.
- VLAN lifecycle: active `vlan_lifecycle_snapshots.plan_fingerprint`.
- Subscriber route export: active
  `subscriber_route_export_snapshots.plan_fingerprint`.
- Controller sync: controller runtime status state hash.

Post-apply drift verification is enabled by default. `auto_rollback_on_drift`
is available for strict environments, but remains off by default so operators
can review controller or device-side differences before compensation.

## API

Read the current transaction plan and evidence:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/enforcement-transactions \
  | jq '.report.status, .report.summary, .report.evidence.summary'
```

Preview selected targets:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targets":["vlan_lifecycle","subscriber_route_export","runtime_qos","runtime_firewall"]}' \
  http://127.0.0.1:8083/api/v1/system/enforcement-transactions/preview \
  | jq '.result.status, .result.plan.summary, .result.steps'
```

Apply selected targets atomically:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targets":["vlan_lifecycle","subscriber_route_export","runtime_qos","runtime_firewall"]}' \
  http://127.0.0.1:8083/api/v1/system/enforcement-transactions/apply \
  | jq '.result.status, .result.transaction_id, .result.steps, .result.drift'
```

Detect drift:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targets":["vlan_lifecycle","subscriber_route_export","runtime_qos","runtime_firewall","controller_sync"]}' \
  http://127.0.0.1:8083/api/v1/system/enforcement-transactions/drift \
  | jq '.result.status, .result.drift'
```

Rollback a specific transaction:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"transaction_id":"enf-apply-example"}' \
  http://127.0.0.1:8083/api/v1/system/enforcement-transactions/rollback \
  | jq '.result.status, .result.steps'
```

List transaction and drift history:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/enforcement-transactions/history?limit=50' \
  | jq '.summary, .transactions[0:5], .drift_events[0:5]'
```

## Configuration

```yaml
policy:
  enforcement_transactions:
    enabled: true
    fail_closed: true
    targets: ["vlan_lifecycle", "subscriber_route_export", "runtime_qos", "runtime_firewall", "controller_sync"]
    require_preview_before_apply: true
    auto_rollback_on_failure: true
    auto_rollback_on_drift: false
    drift_check_after_apply: true
    drift_tolerance_seconds: 60
    apply_timeout_seconds: 120
    rollback_timeout_seconds: 120
    history_retention_limit: 5000
    compensation_retention_limit: 1000
```

## Database

Schema v63 adds:

- `enforcement_transactions`
- `enforcement_transaction_steps`
- `enforcement_drift_events`

The schema stores operation, status, actor, counts, plan fingerprint, request
JSON, plan JSON, result JSON, diagnostics, per-target snapshots, rollback
support, drift state, and timestamps.

## Operations

Use the atomic apply endpoint for manual enforcement changes after the
individual target previews are clean. Treat `blocked` as fail-closed. Treat
`degraded` as a review-required condition; first deployment can be degraded
because active snapshots do not exist yet.

Support bundles include:

- `api/enforcement-transactions.json`
- `api/enforcement-transactions-history.json`

Production readiness check:

- `atomic_enforcement_transactions`

Automated software gate:

```bash
make test-atomic-enforcement-transactions
```

Release certification evidence is tracked in
`nas-0058-release-certification-checklist.md`.
