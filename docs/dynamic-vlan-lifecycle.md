# Dynamic VLAN Bridge And Subinterface Lifecycle

NAS-0053 completes the software path for turning VLAN intent into local Linux
bridge, VLAN subinterface, and hostapd dynamic VLAN file state. RADIUS replies
can already carry VLAN assignments; this feature makes the appliance enforce
the same intent locally when AegisNAS owns the downstream access interface.

## Scope

Implemented software scope:

- Standard VLAN intent from `vlans`, roles, policy rules, wireless SSIDs, and
  enabled vendor extended VLAN mappings is collected into one normalized plan.
- Dynamic hostapd SSIDs cause the lifecycle planner to generate a managed
  `vlan_file` inventory for all configured VLAN intent.
- Linux bridge and 802.1Q subinterface names are validated against safe kernel
  interface-name rules.
- Long generated subinterface names are shortened deterministically while
  preserving the parent interface and VLAN ID in the command plan.
- Preview records evidence without changing host state.
- Apply executes idempotent `ip link` commands, writes the managed hostapd VLAN
  file atomically, stores an active snapshot, and records event history.
- Rollback restores a selected snapshot, or the newest previous restorable
  snapshot when none is specified.
- Snapshots store summary JSON, diagnostics JSON, command text, hostapd file
  contents, artifact SHA-256, full normalized plan JSON, actor, timestamps, and
  previous snapshot linkage.
- Admin API, OpenAPI, RBAC, production-readiness, support-bundle,
  system-status, Dashboard, config defaults, and schema evidence are
  implemented.

External Linux bridge/VLAN, hostapd, FreeRADIUS, vendor AP/switch/controller,
HA, performance, soak, security, production deployment, and customer validation
are tracked in `nas-0053-release-certification-checklist.md`.

## Standards And Attributes

Dynamic VLAN assignment is based on standard RADIUS tunnel attributes:

- `Tunnel-Type = VLAN`
- `Tunnel-Medium-Type = IEEE-802`
- `Tunnel-Private-Group-Id = <vlan>`
- `Egress-VLANID` where a device supports tagged egress VLAN semantics

The AegisNAS product dictionary also carries `AegisNAS-VLAN`. Vendor packs can
contribute equivalent VLAN intent, including Extreme
`Extreme-Netlogin-Extended-Vlan`, HP `Egress-VLANID`, Cambium VLAN attributes,
Aruba VLAN replies, Ruckus VLAN hints, UniFi/UBNT VLAN values, and other
dictionary-backed VLAN fields.

Relevant RFCs:

- RFC 2865, RADIUS
- RFC 2866, RADIUS Accounting
- RFC 2868, RADIUS tunnel attributes
- RFC 5176, Dynamic Authorization Extensions

## API

Read current status, preview, and evidence:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vlan-lifecycle \
  | jq '.report.plan.status, .report.plan.summary, .evidence.summary'
```

Preview without changing Linux or hostapd state:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/vlan-lifecycle/preview \
  | jq '.event_id, .plan.status, .plan.commands, .plan.hostapd_vlan_file_text'
```

Apply the owned bridge/subinterface lifecycle:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operation":"apply"}' \
  http://127.0.0.1:8083/api/v1/system/vlan-lifecycle/apply \
  | jq '.result.status, .result.snapshot_id, .result.previous_snapshot_id'
```

Rollback to a known snapshot:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_id":"vlan-snap-id"}' \
  http://127.0.0.1:8083/api/v1/system/vlan-lifecycle/rollback \
  | jq '.result.status, .result.restored_snapshot_id'
```

List history:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vlan-lifecycle/history \
  | jq '.summary, .snapshots[0:5], .events[0:10]'
```

Read-only administrators can view status and preview. `ops_admin` or
`super_admin` is required for apply and rollback.

## Configuration

Enable local lifecycle management only on appliances where AegisNAS owns the
downstream LAN or trunk interface:

```yaml
policy:
  runtime_vlan_lifecycle_enabled: true

lan:
  name: eth1

wireless:
  hostapd_vlan_file_path: /etc/hostapd/aegisnas-vlans.conf
```

If `lan.name` is empty, the planner falls back to `wan.name` as the lifecycle
parent for single-trunk deployments. Invalid VLAN IDs, unsafe interface names,
conflicting bridge mappings, and missing parent interfaces block apply.

## Hostapd

When an enterprise SSID enables `dynamic_vlan`, generated hostapd config now
includes:

```text
dynamic_vlan=1
vlan_file=/etc/hostapd/aegisnas-vlans.conf
```

The lifecycle apply writes that file with lines in the form:

```text
20 br-vlan20 wlan0.20
30 br-corp wlan0.30
```

The generated VLAN file is owned by AegisNAS. Operators should not edit it by
hand; edit VLAN catalog, role, policy, vendor mapping, or SSID intent and then
preview/apply again.

## Database

Schema v58 adds:

- `vlan_lifecycle_snapshots`
- `vlan_lifecycle_events`

Snapshots store active rollback state and complete plan evidence. Events store
preview, apply, sync, rollback, blocked, failed, degraded, and skipped history.

## Operations

Support bundles include:

- `api/vlan-lifecycle.json`
- `api/vlan-lifecycle-history.json`

Dashboard includes:

- Dynamic VLAN lifecycle status
- VLAN, bridge, subinterface, hostapd entry, command, and diagnostic counts
- active snapshot ID
- parent interface
- hostapd VLAN file path

Production readiness includes `dynamic_vlan_lifecycle`.

## Validation

Automated software validation covers:

- normalized VLAN intent collection from config, wireless, roles, policy rules,
  and vendor extended mappings
- unsafe VLAN ID and bridge-name blocking
- deterministic short subinterface naming
- hostapd `dynamic_vlan` and `vlan_file` rendering
- DB migration, snapshot, event, and summary evidence
- API status, preview, history, readiness, RBAC, OpenAPI, and support bundle
  behavior
- Dashboard and settings UI build integration

Release certification covers real Linux bridge/VLAN command execution, hostapd
dynamic VLAN behavior, FreeRADIUS packet interoperability, vendor devices and
controllers, HA failover, performance, soak, security review, and production
acceptance.
