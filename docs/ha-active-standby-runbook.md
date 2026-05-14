# HA Active/Standby Runbook

This runbook is the operator path for AegisNAS high availability with:

- active and standby roles
- VIP takeover
- VIP announcement refresh after takeover
- continuous shared replication freshness tracking
- staged standby activation
- optional standby auto-activation during failover
- post-failover health validation with automatic standby rollback
- HA history and export

Use this with:

- [Ubuntu VM Deployment And Full Flow Test Runbook](ubuntu-vm-runbook.md)
- [VMware Workstation 17 Player Full Product Runbook](vmware-workstation-17-player-full-test.md)
- [Operations Guide](operations.md)

## What This HA Guide Covers

This guide covers:

1. how to shape an active and standby pair
2. how to configure shared HA state
3. how to publish and stage replication packages
4. how to activate the standby safely
5. how to validate pair upgrades
6. how to run failover and recovery drills
7. how to read the HA dashboard, history, and export data

Important boundary:

- continuous HA replication publishes and stages fresh state
- manual standby activation is always available
- optional auto-activation only runs on a standby during a real failover promotion path
- that keeps the standby calm during normal replication while still letting it promote with fresh state when the active node really disappears

## Target Shape

Use two nodes:

```text
Active node  -> serves traffic, publishes shared HA package
Standby node -> watches peer, tracks package freshness, stages and activates package
```

Shared requirements:

- same product version
- same schema generation support
- shared HA state directory reachable by both nodes
- peer admin API URLs reachable between nodes
- one VIP planned on the shared serving subnet

## Minimum Config Fields

Set these on both nodes:

```yaml
high_availability:
  enabled: true
  role: active | standby
  peer_api_url: "http://<peer-ip>:8083"
  virtual_ip: "192.168.50.2"
  heartbeat_interval_seconds: 5
  failover_timeout_seconds: 20
  replication_interval_seconds: 300
  replication_stale_after_seconds: 900
  split_brain_protection_enabled: true
  auto_stage_shared_package: true
  auto_activate_on_failover: false
  replication_signing_key_env: "AEGIS_HA_REPLICATION_SIGNING_KEY"
  replication_encryption_key_env: "AEGIS_HA_REPLICATION_ENCRYPTION_KEY"
  witness_api_url: "https://witness.example.test/ha"
  witness_urls:
    - "https://witness-a.example.test/ha"
    - "https://witness-b.example.test/ha"
  witness_quorum: 2
  witness_weights:
    "https://witness-a.example.test/ha": 3
    "https://witness-b.example.test/ha": 1
  witness_weight_threshold: 4
  witness_groups:
    "https://witness-a.example.test/ha": "dc-a"
    "https://witness-b.example.test/ha": "dc-b"
  witness_min_distinct_groups: 2
  witness_sources:
    "https://witness-a.example.test/ha": "local"
    "https://witness-b.example.test/ha": "external"
  witness_source_confidence:
    "local": "critical"
    "external": "advisory"
  witness_required_sources:
    - "local"
    - "external"
  witness_policy_mode: "all"
  witness_failure_tolerance: 1
  witness_failure_weight_tolerance: 1
  witness_min_approvals_by_tier:
    "critical": 1
  witness_min_weight_by_tier:
    "critical": 3
  witness_max_age_by_tier:
    "critical": 10
    "advisory": 30
  witness_failure_tolerance_by_tier:
    "advisory": 1
  witness_failure_weight_tolerance_by_tier:
    "advisory": 1
  witness_blocking_tiers:
    - "critical"
  witness_token_env: "AEGIS_HA_WITNESS_TOKEN"
  witness_signing_key_env: "AEGIS_HA_WITNESS_SIGNING_KEY"
  witness_max_age_seconds: 30
  witness_required_node: "witness-1"
  witness_replay_protection_enabled: true
  preempt: false
  preempt_holdoff_seconds: 0
  shared_state_dir: "/var/lib/aegisnas/ha"
```

Guidance:

- `heartbeat_interval_seconds`: how often the local node probes the peer
- `failover_timeout_seconds`: how long a standby waits before declaring failover active
- `replication_interval_seconds`: how often the active node publishes a fresh shared package
- `replication_stale_after_seconds`: when the shared package is considered stale
- `split_brain_protection_enabled`: whether standby nodes require the peer shared heartbeat to go stale before promoting
- `auto_stage_shared_package`: whether the standby keeps the freshest shared package staged automatically
- `auto_activate_on_failover`: whether the standby activates that fresh staged package before claiming the VIP during failover
- `replication_signing_key_env`: optional shared HMAC key env used to sign and verify HA replication bundles
- `replication_encryption_key_env`: optional shared env used to encrypt HA replication bundles before they are written to shared storage or downloaded for standby import
- `witness_api_url`: optional external witness that must explicitly allow standby promotion during a failover window; this requires split-brain protection to stay enabled
- `witness_urls`: optional multi-witness list; when populated, the standby consults this set instead of the single `witness_api_url`
- `witness_quorum`: minimum number of configured witnesses that must allow promotion
- `witness_weights`: optional per-witness weight overrides keyed by witness URL; unspecified witnesses count as weight `1`
- `witness_weight_threshold`: optional minimum combined witness weight required in addition to the plain witness quorum count
- `witness_groups`: optional per-witness group overrides keyed by witness URL; unspecified witnesses count as their own distinct group
- `witness_min_distinct_groups`: optional minimum number of distinct witness groups that must allow promotion in addition to the plain witness quorum and weight rules
- `witness_sources`: optional per-witness source overrides keyed by witness URL; unspecified witnesses count as their own source
- `witness_source_confidence`: optional source-to-confidence-tier mapping; unspecified sources use the `standard` tier
- `witness_required_sources`: optional source classes that must all be represented in witness approvals before promotion is allowed
- `witness_policy_mode`: how group and source diversity rules combine; `all` requires every configured family, `any` accepts either family, and `group_only` / `source_only` make one family authoritative
- `witness_failure_tolerance`: optional count of failed witness probes that may reduce the required quorum during promotion
- `witness_failure_weight_tolerance`: optional failed witness weight budget that may reduce the effective weight threshold during promotion
- `witness_min_approvals_by_tier`: optional per-tier approval floors; promotion must include at least this many approvals from each listed confidence tier
- `witness_min_weight_by_tier`: optional per-tier weight floors; promotion must include at least this much witness weight from each listed confidence tier
- `witness_max_age_by_tier`: optional per-tier freshness overrides in seconds; tiers without overrides fall back to `witness_max_age_seconds`
- `witness_failure_tolerance_by_tier`: optional per-tier failed witness count budgets; tiers without overrides fall back to `witness_failure_tolerance`
- `witness_failure_weight_tolerance_by_tier`: optional per-tier failed witness weight budgets; tiers without overrides fall back to `witness_failure_weight_tolerance`
- `witness_blocking_tiers`: optional confidence tiers whose explicit witness denies block standby promotion immediately even when other witnesses would otherwise satisfy quorum
- `witness_token_env`: optional bearer token env used when the external witness requires authenticated requests
- `witness_signing_key_env`: optional shared HMAC key env used to verify the witness response body before standby promotion is allowed
- `witness_max_age_seconds`: optional maximum allowed age for the witness `observed_at` timestamp; if the response is older, or missing `observed_at`, standby promotion is blocked
- `witness_required_node`: optional expected `witness_node` identity; if the response comes from a different witness identity, standby promotion is blocked
- `witness_replay_protection_enabled`: when enabled, the standby sends a one-time witness challenge and requires the signed response body to echo it exactly before promotion is allowed
- `preempt: false`: safer default for most labs and branch environments
- `preempt_holdoff_seconds`: optional delay before a recovered active node reclaims the VIP when `preempt: true`

## Shared State Directory

The shared state directory must be reachable on both nodes.

Typical choices:

- shared disk
- clustered filesystem
- NFS mount in a lab

Current HA artifacts live under:

```text
<shared_state_dir>/vip-lease.json
<shared_state_dir>/heartbeats/active.json
<shared_state_dir>/heartbeats/standby.json
<shared_state_dir>/replication/live/latest.tar.gz
<shared_state_dir>/replication/live/latest.json
<shared_state_dir>/replication/staged/
<shared_state_dir>/replication/backups/
```

## Bootstrap Sequence

Do the active node first.

1. deploy the active node
2. confirm services are healthy
3. confirm `Dashboard -> High Availability` shows:
   - configured role `active`
   - effective role `active`
   - VIP assigned locally
   - shared replication package published

Then deploy the standby node.

1. deploy the standby node
2. confirm services are healthy
3. confirm `Dashboard -> High Availability` shows:
   - configured role `standby`
   - effective role `standby`
   - VIP not assigned locally
   - shared package freshness visible

## Shared Replication Workflow

### Active Node

The active node now publishes the shared replication package continuously.

Expected operator view:

- `Dashboard -> High Availability`
- replication status is `ok`
- latest source node is the active node
- package age stays below the stale threshold
- when content and HA protection keys are unchanged, `publish_mode` can show `reused`, meaning freshness was refreshed without rewriting the shared package payload

### Standby Node

The standby node can stage the latest shared package without manual upload.

UI path:

```text
Backups -> Standby Replication Package -> Stage Latest Shared Package
```

Expected result:

- a new staged package appears under `Staged HA Packages`
- source node and schema version match the active node
- encryption status is `decrypted` when bundle encryption is enabled
- summary confirms the package is ready

## Standby Activation

Activation can be manual or failover-driven.

UI path:

```text
Backups -> Staged HA Packages -> Activate On Standby
```

What activation does:

- captures a standby safety rollback package first
- lays down the imported config and database
- preserves the local HA role, peer URL, and database path
- schedules service restart

After activation:

1. refresh `Backups`
2. confirm the staged package shows `activated`
3. confirm the safety backup path is shown
4. confirm `Dashboard -> High Availability` still reports standby role and a fresh shared package

### Automatic Activation During Failover

If this is enabled:

```yaml
high_availability:
  auto_stage_shared_package: true
  auto_activate_on_failover: true
```

Then the standby promotion path becomes:

1. peer health fails long enough to cross `failover_timeout_seconds`
2. standby checks the freshest shared package
3. standby requires that the shared package is fresh, not stale
4. standby activates the matching staged package, or stages then activates it
5. standby queues the HA restart handoff
6. after restart, the standby validates core service health before it keeps the promoted state
7. if validation passes, the standby can reclaim the VIP with the activated state
8. if validation fails, the standby restores its last known-good rollback bundle and restarts again

Important safety boundary:

- this does not auto-activate on every publish
- it only auto-activates when the standby is genuinely promoting during failover
- if restart handoff fails, HA runtime will say so and VIP takeover will not quietly pretend everything is fine
- if the promoted standby comes back unhealthy after restart, HA runtime records the failure and automatically restores the standby rollback bundle

## HA Smoke Helper

Use the helper script on each node:

```bash
sudo bash scripts/ha-active-standby-smoke-test.sh --role active
sudo bash scripts/ha-active-standby-smoke-test.sh --role standby
```

On the standby, you can also stage the shared package through the helper:

```bash
sudo bash scripts/ha-active-standby-smoke-test.sh --role standby --stage-shared
```

And for a full standby package path:

```bash
sudo bash scripts/ha-active-standby-smoke-test.sh --role standby --stage-shared --activate-latest
```

The script:

- captures local service and network state
- verifies health endpoints
- saves HA API responses
- records replication freshness
- optionally stages the latest shared package on a standby node
- optionally activates the latest staged package on a standby node

Output location:

```text
/var/tmp/aegisnas-ha-smoke/<timestamp>-active/
/var/tmp/aegisnas-ha-smoke/<timestamp>-standby/
```

Useful files:

- `summary.json`
- `api/system-status.json`
- `api/ha-replication-shared.json`
- `api/ha-replication-staged.json`
- `api/ha-history.json`
- `api/ha-stage-shared.json` when staging is requested
- `api/ha-activate-latest.json` when activation is requested

## HA Pair Upgrade Validation

After both nodes have been upgraded, use the pair-aware validation helper from the active node:

```bash
sudo bash scripts/ha-pair-upgrade-validate.sh
```

For a stronger pass that also proves peer schema and peer service status over SSH:

```bash
sudo bash scripts/ha-pair-upgrade-validate.sh --peer-ssh ubuntu@192.168.50.12
```

If you want the standby refreshed and activated before the post-upgrade drill:

```bash
sudo bash scripts/ha-pair-upgrade-validate.sh \
  --peer-ssh ubuntu@192.168.50.12 \
  --stage-shared-peer \
  --activate-latest-peer
```

Optional post-upgrade HA exercise:

```bash
sudo bash scripts/ha-pair-upgrade-validate.sh --run-failover-drill
sudo bash scripts/ha-pair-upgrade-validate.sh --run-soak-cycles 3
```

What the helper validates:

- local schema version against the repo migration version
- local service and health status
- peer HA status through the admin API
- shared replication and staged-package visibility
- optional peer schema and service status through SSH
- optional failover or soak validation after the pair checks pass

Important boundary:

- this helper does not SSH in and perform the upgrade for you
- it validates the HA pair after both nodes have already been updated
- `--run-soak-cycles` still requires `preempt: true`

Output location:

```text
/var/tmp/aegisnas-ha-upgrade-validate/<timestamp>/
```

Useful files:

- `summary.json`
- `schema-local.txt`
- `schema-peer.txt` when `--peer-ssh` is used
- `api/local-system-status.json`
- `api/peer-system-status.json`
- `api/local-ha-replication-shared.json`
- `api/peer-ha-replication-staged.json`
- `post-upgrade-failover-artifact-dir.txt` or `post-upgrade-soak-artifact-dir.txt` when an exercise is requested

## Manual Failover Drill

Use a VM console or direct host access for this drill.

Safer test order:

1. confirm standby has a fresh staged and activated package
2. confirm active node currently owns the VIP
3. confirm standby is healthy and idle

The easiest repeatable path is now the dedicated helper on the active node:

```bash
sudo bash scripts/ha-failover-drill.sh
```

What the helper does:

- confirms the local node is currently effective active and holds the VIP
- confirms the peer is currently effective standby
- captures local and peer HA status before the drill
- stops `aegis-gateway` on the active node
- waits for peer promotion and VIP takeover, or for auto-activation restart scheduling when enabled
- optionally starts the original active node again for recovery observation
- stores artifacts under `/var/tmp/aegisnas-ha-failover/<timestamp>/`

Useful files from the helper:

- `summary.json`
- `polls/peer-promoted.json`
- `snapshots/pre-stop-local-status.json`
- `snapshots/post-stop-peer-status.json`
- `snapshots/post-recovery-peer-status.json` when recovery is not skipped

If you want to hold the failed-active state open for manual inspection, use:

```bash
sudo bash scripts/ha-failover-drill.sh --skip-recovery
```

The manual fallback is still valid if you want to drive each step yourself. Simulate active-node failure by stopping the gateway on the active node:

```bash
sudo systemctl stop aegis-gateway
```

Why this drill:

- the gateway owns the VIP controller loop
- stopping only `aegis-admin-api` is not enough to prove full failover behavior

Expected outcome after `failover_timeout_seconds`:

- standby `Dashboard -> High Availability` shows effective role `active`
- standby reports VIP assigned locally
- standby reports VIP announcement status `sent`
- HA history records a promotion
- active node stops serving the VIP

Expected additional outcome when `auto_activate_on_failover: true`:

- standby runtime shows `auto_activate_status`
- HA history records `replication_activate` and `replication_restart`
- HA runtime shows `post_failover_recovery` state
- if the promoted standby is unhealthy after restart, HA history records `post_failover_validation: rolled_back`
- if restart handoff fails, HA runtime should show the failure clearly instead of silently claiming success

Expected additional outcome when `split_brain_protection_enabled: true`:

- standby does not promote while the peer shared heartbeat is still fresh
- standby promotes only after peer health fails and the peer shared heartbeat becomes stale
- runtime details show `fencing_status`, peer heartbeat age, and whether the peer heartbeat is marked stale

Useful checks on standby:

```bash
ip -br addr
curl -fsS http://127.0.0.1:8083/api/v1/system/status -H "Authorization: Bearer <token>"
```

## Repeated HA Soak Drill

When you want to rehearse the failover path more than once, use the soak helper on the active node:

```bash
sudo bash scripts/ha-soak-test.sh --cycles 3
```

Optional standby preparation before cycle 1:

```bash
sudo bash scripts/ha-soak-test.sh \
  --cycles 3 \
  --stage-shared-before-start \
  --activate-latest-before-start
```

What the helper does:

- confirms the local node starts as the effective active node
- optionally stages and activates the latest standby package before the first cycle
- runs `scripts/ha-failover-drill.sh` once per cycle
- captures local and peer HA status plus HA history before and after each cycle
- records the matching failover artifact directory for every cycle
- writes a top-level summary under `/var/tmp/aegisnas-ha-soak/<timestamp>/`

Important boundary:

- repeated cycles from one node require `preempt: true`
- otherwise the peer may remain active after the first recovery and there is no honest second cycle to run from the original node

Useful soak artifacts:

- `summary.json`
- `cycle-summaries.json`
- `cycles/cycle-01/summary.json`
- `cycles/cycle-01/failover-artifact-dir.txt`
- `cycles/cycle-01/failover-artifacts/`

Acceptance checks for a healthy soak run:

- every cycle shows `promotion_result: success`
- when `preempt: true`, every cycle shows `reclaim_status: reclaimed`
- post-cycle local and peer effective roles match the configured preempt policy
- HA history remains coherent across repeated promotion, restart, and recovery events

## Recovery Drill

Bring the original active node back:

```bash
sudo systemctl start aegis-gateway
```

Then watch both dashboards.

Expected behavior with `preempt: false`:

- the recovered node does not instantly steal the VIP back
- the current holder keeps serving until you intentionally change roles or restart the pair

Expected behavior with `preempt: true`:

- the preferred active node may reclaim the VIP
- if `preempt_holdoff_seconds` is greater than `0`, the recovered active node waits through that holdoff before reclaiming
- HA history should show a lease preemption or return event

## HA History And Export

Operator surface:

```text
Backups -> HA History
```

What you get:

- failover promotions
- failover returns
- peer health failures and recoveries
- VIP lease acquisitions, releases, and preemptions
- replication publishes and stale-fresh transitions
- shared package staging and activations
- post-failover validation pass or rollback outcomes

Export options:

- CSV
- JSON

Dashboard also surfaces summary counters under `High Availability`.

## Recommended Acceptance Checks

Mark the HA pair ready when all of these are true:

```text
[ ] active node reports effective role active
[ ] active node reports VIP assigned locally
[ ] active node publishes shared replication package
[ ] standby node reports effective role standby
[ ] standby node reports shared replication package fresh
[ ] standby node reports split-brain protection enabled
[ ] standby can stage latest shared package
[ ] standby activation succeeds
[ ] standby auto-activation behavior matches configuration
[ ] standby safety backup path is recorded
[ ] HA history shows replication publish/stage/activate events
[ ] manual failover promotes standby after timeout
[ ] repeated soak drill passes for the intended cycle count
[ ] recovery behavior matches the configured preempt policy
```

## Troubleshooting

### Shared package not present

Check:

```bash
ls -lah /var/lib/aegisnas/ha/replication/live
sudo journalctl -u aegis-gateway -n 120 --no-pager
```

Verify:

- active node role is really `active`
- shared state directory is writable
- current process can create files there

### Shared package is stale

Check:

```bash
curl -fsS http://127.0.0.1:8083/api/v1/system/status -H "Authorization: Bearer <token>" | jq '.high_availability.replication_runtime'
```

Look for:

- `latest_age_seconds`
- `stale: true`
- publish errors in HA history

### Standby cannot stage latest shared package

Check:

```bash
curl -fsS http://127.0.0.1:8083/api/v1/system/ha/replication-shared -H "Authorization: Bearer <token>"
```

If the package is present but staging fails:

- confirm schema support matches
- confirm the standby can read the shared package path

### Failover did not happen

Check:

- active gateway was really stopped, not just admin API
- standby `failover_timeout_seconds` is long enough to observe
- split-brain protection did not hold the standby back because the peer shared heartbeat was still fresh
- shared VIP lease is visible
- standby gateway logs show peer failure and promotion path

Useful commands:

```bash
sudo journalctl -u aegis-gateway -n 200 --no-pager
ip -br addr
```
