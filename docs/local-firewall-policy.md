# Stateful Per-Session Local Firewall Policy

NAS-0050 makes the Linux gateway firewall an owned enforcement target for
active RADIUS sessions. AegisNAS now compiles enabled ACL policies assigned to
sessions into an `inet` nftables table named `aegis_runtime`, records preview
and apply evidence, and preserves rollback snapshots.

## Scope

Implemented software scope:

- Runtime firewall planner with schema version `1`.
- Owned nftables table: `table inet aegis_runtime`.
- IPv4 and IPv6 quarantine sets.
- Stateful forwarding chain with invalid-state drop and
  `ct state established,related accept`.
- Per-session ACL compilation from normalized `acl_policies`.
- Managed-session default drop after explicit permit and deny rules.
- Quarantine enforcement before connection-state accepts.
- IPv4 and IPv6 session address support from `sessions.ip` and
  `sessions.ipv6_address`.
- Safe compiler diagnostics for missing policies, unsupported protocols,
  invalid address selectors, invalid ports, and family mismatches.
- Deterministic ruleset fingerprints.
- Durable preview/apply/sync/rollback events in `runtime_firewall_events`.
- Durable applied ruleset snapshots in `runtime_firewall_snapshots`.
- Rollback to a selected snapshot or the newest previous applied snapshot.
- Admin API, OpenAPI, RBAC, production-readiness, support-bundle, system-status,
  and Dashboard visibility.

External nftables host validation, FreeRADIUS Linux interop, vendor hardware,
HA, performance, soak, security, production deployment, and customer validation
are tracked in `nas-0050-release-certification-checklist.md` and do not block
engineering completion.

## Enforcement Model

Unmanaged sessions keep the base forward policy of `accept`.

Managed sessions are sessions with `sessions.acl_policy_name` set to an enabled
ACL policy. For those sessions AegisNAS emits:

1. The explicit permit and deny rules from the normalized ACL policy.
2. A default inbound drop for traffic sourced by the session address.
3. A default outbound drop for traffic destined to the session address.

Quarantined sessions are detected by VLAN `99`, a role containing
`quarantine`, or a `Filter-Id` containing `quarantine`. Quarantine drops run
before the stateful established/related accept rule, so reclassified sessions
are cut off even when flows already exist.

## API

Read current status and evidence:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/runtime-firewall \
  | jq '.report.status, .report.summary, .report.evidence.summary'
```

Preview without changing nftables:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/runtime-firewall/preview \
  | jq '.event_id, .plan.status, .plan.ruleset_fingerprint'
```

Apply the compiled ruleset:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/runtime-firewall/apply \
  | jq '.result.status, .result.snapshot_id, .result.previous_snapshot_id'
```

Rollback:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_id":"fw-snap-example"}' \
  http://127.0.0.1:8083/api/v1/system/runtime-firewall/rollback \
  | jq '.result.status, .result.restored_snapshot_id'
```

History:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/runtime-firewall/history?limit=50' \
  | jq '.summary, .snapshots[0:5], .events[0:5]'
```

## Database

Schema v55 adds:

- `runtime_firewall_snapshots`
- `runtime_firewall_events`

Snapshots store the exact ruleset text, fingerprint, active flag, previous
snapshot, actor, counts, diagnostics, and apply/rollback timestamps. Events
store operation history, status, snapshot linkage, counts, diagnostics, and
operation details.

## Operations

Use preview before every manual apply. Treat `blocked` as fail-closed and fix
diagnostics before attempting to apply. Treat `degraded` as operationally
usable only when the warning is reviewed and accepted.

Support bundles include:

- `api/runtime-firewall.json`
- `api/runtime-firewall-history.json`
- `system/nft-ruleset.txt`

Production readiness includes the `stateful_local_firewall` check.

## Testing

Automated software coverage includes:

- Quarantine-only compatibility.
- Dual-stack per-session ACL compilation.
- Missing-policy fail-closed behavior.
- nftables apply failure handling.
- Snapshot creation and active snapshot replacement.
- Rollback to a previous snapshot.
- Runtime status details.
- Admin API status, preview, history, OpenAPI, RBAC, support-bundle, and
  readiness tests.
- Schema migration and evidence-summary tests.
- Dashboard TypeScript build coverage.

Packet captures, real nftables smoke tests, real AP/controller tests, HA drills,
and long-duration load evidence belong in the release certification checklist.
