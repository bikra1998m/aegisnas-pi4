# Hierarchical QoS And Scheduler Model

NAS-0051 makes runtime bandwidth enforcement a typed hierarchical scheduler
instead of a flat per-session shaper. AegisNAS now compiles active sessions and
their `bandwidth_profile` assignments into Linux `tc`/IFB classes with
aggregate profile classes, per-session leaf classes, `fq_codel` leaf queues,
priority, burst, aggregate caps, deterministic fingerprints, durable evidence,
and rollback snapshots.

## Scope

Implemented software scope:

- Runtime QoS scheduler planner with schema version `1`.
- Backward-compatible use of existing `bandwidth_profiles`.
- Optional per-profile scheduler overrides in `qos_scheduler_profiles`.
- Aggregate download and upload classes per bandwidth profile.
- Per-session download and upload leaf classes under the profile aggregate.
- `fq_codel` leaf qdiscs for latency fairness.
- Priority, burst, committed burst, quantum, DSCP metadata, and aggregate cap
  validation.
- IFB ingress redirect for upload shaping.
- Deterministic command-plan fingerprints.
- Durable preview/apply/sync/rollback events in `runtime_qos_events`.
- Durable applied command snapshots in `runtime_qos_snapshots`.
- Rollback to a selected snapshot or the newest previous applied snapshot.
- Admin API, OpenAPI, RBAC, production-readiness, support-bundle, system-status,
  and Dashboard visibility.

Dual-stack classifier expansion, exact vendor rate-unit compilers, and
controller reconciliation are handled by later roadmap features. External
Linux `tc` validation, packet captures, vendor/controller labs, HA,
performance, soak, security, production deployment, and customer validation are
tracked in `nas-0051-release-certification-checklist.md`.

## Scheduler Model

`bandwidth_profiles` remain the source for per-session rate names:

- `download_rate_kbps`
- `upload_rate_kbps`
- `burst_kb`

`qos_scheduler_profiles` can add production scheduler behavior without
breaking existing profiles:

- `parent_profile_name`
- `scheduler`
- `priority`
- `dscp_mark`
- `download_min_rate_kbps`
- `download_ceil_rate_kbps`
- `upload_min_rate_kbps`
- `upload_ceil_rate_kbps`
- `burst_kb`
- `cburst_kb`
- `quantum_bytes`
- `metadata_json`

If no scheduler override exists, AegisNAS derives a safe hierarchy from the
bandwidth profile. The aggregate class ceiling defaults to the per-session
rate multiplied by the number of active shaped sessions for that profile.

## API

Read current status and evidence:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/qos-scheduler \
  | jq '.report.status, .report.summary, .report.evidence.summary'
```

Preview without changing `tc` state:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/qos-scheduler/preview \
  | jq '.event_id, .plan.status, .plan.plan_fingerprint'
```

Apply the compiled scheduler plan:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/qos-scheduler/apply \
  | jq '.result.status, .result.snapshot_id, .result.previous_snapshot_id'
```

Rollback:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_id":"qos-snap-example"}' \
  http://127.0.0.1:8083/api/v1/system/qos-scheduler/rollback \
  | jq '.result.status, .result.restored_snapshot_id'
```

List history:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/qos-scheduler/history?limit=50' \
  | jq '.summary, .snapshots[0:5], .events[0:5]'
```

Create or update a scheduler override:

```bash
curl -fsS -X PUT -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "scheduler": "htb",
    "priority": 1,
    "dscp_mark": 46,
    "download_ceil_rate_kbps": 30000,
    "upload_ceil_rate_kbps": 10000,
    "burst_kb": 256,
    "cburst_kb": 256,
    "metadata": {"owner": "network-ops"}
  }' \
  http://127.0.0.1:8083/api/v1/system/qos-scheduler/profiles/voice
```

## Operations

Use preview before every manual apply. Treat `blocked` as fail-closed and fix
diagnostics before attempting to apply. Treat `degraded` as usable only after
reviewing the warning. `skipped` means runtime shaping is disabled or no
downstream interface is configured.

Support bundles include:

- `api/qos-scheduler.json`
- `api/qos-scheduler-history.json`

Dashboard includes a Hierarchical QoS Scheduler card under runtime
enforcement.

## Database

Schema v56 adds:

- `qos_scheduler_profiles`
- `runtime_qos_snapshots`
- `runtime_qos_events`

Snapshots store the exact command plan, fingerprint, active flag, previous
snapshot, actor, counts, diagnostics, summary, and apply/rollback timestamps.
Events store preview/apply/sync/rollback history with diagnostics and operation
details.

## Validation

Automated software validation covers:

- migration and schema repair
- scheduler profile CRUD persistence
- profile aggregate and per-session class compilation
- deterministic plan fingerprints
- preview event recording
- API status/history/profile/RBAC/OpenAPI/support-bundle behavior
- production readiness reporting
- UI build integration

Release certification covers host `tc` packet captures, traffic throughput,
hardware/controller smoke testing, HA ownership, long-duration soak, and
production acceptance evidence.
