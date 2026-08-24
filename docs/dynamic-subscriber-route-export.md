# Dynamic Subscriber Route Export

NAS-0059 publishes active subscriber route ownership into BGP, OSPF, and
OSPF3 routing plans. It turns the per-session route and VRF ownership ledger
from NAS-0055 into an operational route-export artifact with preview, apply,
withdrawal, rollback, history, readiness, support-bundle, and atomic
transaction support.

## Scope

Implemented software scope:

- Subscriber route export planner with schema version `1`.
- Route source of truth from active `route_policy_ownership` rows.
- Dual-stack route validation for `Framed-Route` and `Framed-IPv6-Route`
  ownership records.
- BGP, OSPF, and OSPF3 protocol definitions with VRF, route-map, address
  family, community, metric, MED, and local-preference controls.
- Route dampening by minimum route age and suppressed-route limits.
- Withdrawal planning by comparing desired routes with the active export
  snapshot.
- Managed FRR artifact rendering for static routes, prefix lists, route maps,
  BGP redistribution, OSPF redistribution, and OSPF3 redistribution.
- Gated live apply with `file` and `frr-vtysh` drivers.
- Durable snapshots in `subscriber_route_export_snapshots`.
- Durable events in `subscriber_route_export_events`.
- Runtime status, system status, production readiness, OpenAPI, RBAC, support
  bundles, Access Settings, and CI-ready automated tests.
- Atomic enforcement participation as `subscriber_route_export`.

External FRRouting convergence, route reflection, physical FIB installation,
vendor router behavior, HA failover drills, performance, soak, security review,
production deployment, and customer validation are tracked in
`nas-0059-release-certification-checklist.md` and do not block engineering
completion.

## Architecture

The route policy compiler owns per-session route intent and writes active rows
to `route_policy_ownership`. Accounting Stop and Accounting-Off withdraw those
rows when `radius.route_policy.stop_withdrawal` is enabled.

The subscriber route export planner reads active ownership rows, validates the
route family, prefix, gateway, VRF, owner, and revision, then matches each route
to enabled protocol definitions:

- `bgp` accepts IPv4 and IPv6 families.
- `ospf` accepts IPv4.
- `ospf3` accepts IPv6.
- `vrf: all` matches every route VRF.
- Explicit VRFs publish only matching route ownership records.

The planner renders a deterministic FRR artifact and records a
`plan_fingerprint`. When apply is enabled, the `file` driver writes the managed
artifact atomically, and the `frr-vtysh` driver invokes configured `vtysh`
commands. Apply is disabled by default so production operators can review
route export output before any live routing mutation.

## Configuration

```yaml
radius:
  route_policy:
    enabled: true
    stop_withdrawal: true
    dynamic_routing:
      enabled: true
      apply_enabled: false
      driver: file
      artifact_path: /var/lib/aegisnas/routing/subscriber-routes.frr
      vtysh_path: vtysh
      max_exported_routes: 4096
      dampening:
        enabled: true
        min_route_age_seconds: 3
        max_suppressed_routes: 1024
      protocols:
        - protocol: bgp
          enabled: true
          vrf: all
          asn: 65000
          route_map: AEGISNAS-SUBSCRIBER
          address_families: [ipv4, ipv6]
          communities: [no-export]
          metric: 100
          local_preference: 100
```

`apply_enabled: false` is production-safe. It still allows preview, evidence,
history, support-bundle capture, readiness reporting, and atomic transaction
planning. Set it to `true` only after the NAS-0059 release certification
checklist has validated the FRR target and routing domain.

## API

Read current route export state and evidence:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/subscriber-route-export \
  | jq '.report.status, .report.summary, .report.evidence.summary'
```

Preview and record an evidence event:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/subscriber-route-export/preview \
  | jq '.event_id, .plan.command_preview, .plan.diagnostics'
```

Apply when live routing mutation is enabled:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/subscriber-route-export/apply \
  | jq '.result.status, .result.snapshot_id, .result.plan.summary'
```

Rollback to a stored snapshot:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_id":"route-export-snap-example"}' \
  http://127.0.0.1:8083/api/v1/system/subscriber-route-export/rollback \
  | jq '.result.status, .result.restored_snapshot_id'
```

List export history:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/subscriber-route-export/history?limit=50' \
  | jq '.summary, .events[0:5], .snapshots[0:5]'
```

Read-only and guest-admin roles may read, preview, and list history.
`ops_admin` and `super_admin` may apply and rollback.

## Atomic Enforcement

The `subscriber_route_export` participant runs after `vlan_lifecycle` and
before QoS, firewall, and controller sync by default:

```yaml
policy:
  enforcement_transactions:
    targets:
      - vlan_lifecycle
      - subscriber_route_export
      - runtime_qos
      - runtime_firewall
      - controller_sync
```

Atomic preview includes route export plan fingerprints, route counts, command
counts, diagnostics, and active snapshot drift. If route export live apply is
gated, the participant is recorded as skipped rather than mutating routing
state.

## Database

Schema v64 adds:

- `subscriber_route_export_snapshots`
- `subscriber_route_export_events`

Snapshots store the rendered artifact, commands, plan JSON, diagnostics,
summary, actor, previous snapshot, apply timestamp, rollback timestamp, active
state, and fingerprints. Events store preview, apply, sync, rollback, skipped,
blocked, degraded, and failed evidence.

## Operations

1. Compile route policy and confirm active ownership in
   `/api/v1/system/route-policy/history`.
2. Preview subscriber route export and inspect `artifact_text`,
   `command_preview`, `diagnostics`, and `withdrawals`.
3. Keep `apply_enabled: false` until FRR and routing-domain validation are
   complete.
4. Enable `apply_enabled` and run a direct route-export apply or an atomic
   enforcement apply.
5. Review `/api/v1/system/subscriber-route-export/history` and
   `/api/v1/system/status`.
6. Roll back by `snapshot_id` if the active route export artifact or routing
   daemon state must be restored.

Support bundles include:

- `api/subscriber-route-export.json`
- `api/subscriber-route-export-history.json`

Production readiness check:

- `dynamic_subscriber_route_export`

Automated software gate:

```bash
make test-subscriber-route-export
```
