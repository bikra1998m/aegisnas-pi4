# Hostapd Dynamic VLAN Lifecycle

NAS-0074 completes the software implementation for local hostapd dynamic VLAN
lifecycle management. It turns enterprise SSID VLAN intent into a previewable,
audited, rollback-capable Linux bridge/subinterface plan and a managed hostapd
`vlan_file`.

## Software Scope

Implemented software behavior:

- WPA2/WPA3 Enterprise SSIDs with `dynamic_vlan: true` are discovered and
  represented as hostapd dynamic VLAN bindings.
- SSIDs with a fallback VLAN render `dynamic_vlan=1`, allowing hostapd to place
  sessions without a returned VLAN onto the configured fallback VLAN.
- SSIDs without a fallback VLAN render `dynamic_vlan=2`, requiring RADIUS to
  return an accepted VLAN and failing closed otherwise.
- The lifecycle planner blocks hostapd dynamic VLAN rollout when the dynamic
  VLAN lifecycle is disabled, when no downstream parent interface is available,
  or when no managed VLAN file entry can be generated.
- The managed VLAN file includes every local VLAN intent accepted by the
  appliance, including VLAN catalog entries, role VLANs, policy VLANs, wireless
  fallback VLANs, VLAN pools, tagged voice/data VLAN policy, QinQ policy, and
  enabled vendor extended VLAN mappings.
- Hostapd lifecycle reports redact RADIUS shared secrets and personal
  passphrases while preserving the fingerprint of the rendered daemon config.
- Cleanup previews identify obsolete managed bridges and subinterfaces from the
  active snapshot.
- Rollback previews remove newly introduced links and replay the previous
  snapshot command plan.
- Apply executes idempotent `ip link` commands, writes the hostapd VLAN file
  atomically, records an active snapshot, and attempts rollback if a command or
  file write fails.
- Admin API, OpenAPI, RBAC, production readiness, system status, support bundle,
  Access Settings UI, Makefile, CI, and automated tests are implemented.

## Standards And Attributes

Dynamic VLAN assignment relies on the standard RADIUS tunnel attributes used by
enterprise Wi-Fi vendors and hostapd:

- `Tunnel-Type = VLAN`
- `Tunnel-Medium-Type = IEEE-802`
- `Tunnel-Private-Group-Id = <vlan-id-or-name>`
- `Egress-VLANID` for tagged egress VLAN semantics where supported
- `AegisNAS-VLAN` as the product dictionary semantic

Relevant standards:

- RFC 2865, RADIUS
- RFC 2866, RADIUS Accounting
- RFC 2868, RADIUS tunnel attributes
- RFC 5176, Dynamic Authorization Extensions
- IEEE 802.1Q VLAN tagging
- IEEE 802.11 Enterprise WLAN operation

## API

Read the NAS-0074 report:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/hostapd-vlan-lifecycle \
  | jq '.report.status, .report.summary, .report.plan.hostapd_bindings'
```

Record a preview event without changing Linux or hostapd state:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/hostapd-vlan-lifecycle/preview \
  | jq '.event_id, .report.status, .report.plan.cleanup_command_preview'
```

Apply the hostapd dynamic VLAN lifecycle:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/hostapd-vlan-lifecycle/apply \
  | jq '.result.status, .result.snapshot_id, .result.previous_snapshot_id'
```

Rollback to the previous restorable snapshot:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/hostapd-vlan-lifecycle/rollback \
  | jq '.result.status, .result.restored_snapshot_id'
```

List hostapd lifecycle history:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/hostapd-vlan-lifecycle/history \
  | jq '.summary, .snapshots[0:5], .events[0:10]'
```

Read-only and guest administrators can read and preview. `ops_admin` or
`super_admin` is required for apply and rollback.

## Configuration

Local hostapd dynamic VLANs require AegisNAS to own the downstream interface:

```yaml
policy:
  runtime_vlan_lifecycle_enabled: true

lan:
  name: eth1

wireless:
  enabled: true
  interface: wlan0
  hostapd_config_path: /etc/hostapd/hostapd.conf
  hostapd_vlan_file_path: /etc/hostapd/aegisnas-vlans.conf
  ssids:
    - name: Corp
      auth_mode: wpa2-enterprise
      vlan: 30
      bridge: br-corp
      dynamic_vlan: true
    - name: Research
      auth_mode: wpa3-enterprise
      dynamic_vlan: true
```

`Corp` renders optional dynamic VLAN with fallback:

```text
dynamic_vlan=1
vlan_file=/etc/hostapd/aegisnas-vlans.conf
```

`Research` renders fail-closed dynamic VLAN:

```text
dynamic_vlan=2
vlan_file=/etc/hostapd/aegisnas-vlans.conf
```

## Operations

Recommended rollout order:

1. Configure VLAN catalog, role/policy VLANs, and dynamic VLAN SSIDs.
2. Run `/api/v1/system/hostapd-vlan-lifecycle/preview`.
3. Confirm `status=ready`, non-empty `hostapd_vlan_entries`, expected
   fallback/fail-closed bindings, and no blocking diagnostics.
4. Apply `/api/v1/system/hostapd-vlan-lifecycle/apply`.
5. Write or publish hostapd configuration.
6. Use RADIUS test users to verify `Tunnel-Type`, `Tunnel-Medium-Type`, and
   `Tunnel-Private-Group-Id` decisions before admitting production clients.

Support bundles include:

- `api/hostapd-vlan-lifecycle.json`
- `api/hostapd-vlan-lifecycle-history.json`
- `api/vlan-lifecycle.json`
- `api/vlan-lifecycle-history.json`

Production readiness includes `hostapd_dynamic_vlan_lifecycle`.
`/api/v1/system/status` reports the same state under
`wireless.hostapd_vlan_lifecycle`.

## Release Certification Checklist

External validation is tracked in
`nas-0074-release-certification-checklist.md`. Real radios, AP/controller
firmware, production Linux networking, HA failover, packet captures,
performance benchmarks, long-duration soak tests, security audit, production
deployment, and customer acceptance are release certification activities. They
do not block NAS-0074 software completion.
