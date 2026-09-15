# RF, RRM, Mesh, And Radio Planning

NAS-0079 adds production software governance for RF/RRM, mesh, and radio
planning across local-radio and external-controller estates. It turns declared
AP/radio topology, band policy, channel pools, power bounds, mesh roots, and
client-steering intent into deterministic preview/apply evidence.

## Purpose

Enterprise WLAN vendors expose channel, power, mesh, and client-steering
controls through controller APIs, AP firmware, and vendor-specific operating
models. Without a vendor-neutral planning layer, operators cannot review radio
intent, compare it with controller ownership boundaries, or keep repeatable
evidence before firmware-specific validation.

NAS-0079 provides that software layer. Real spectrum survey data, physical AP
telemetry, packet captures, firmware behavior, and customer environment proof
remain release certification activities.

## Covered Software Scope

- RF configuration under `wireless.rf` for monitor/enforce mode, fail-closed
  governance, channel-plan mode, default width, power bounds, target RSSI,
  channel reuse, max clients, and history retention.
- Band profiles for 2.4 GHz, 5 GHz, and 6 GHz channel pools, channel width,
  DFS allowance, power limits, and client budgets.
- AP/radio inventory with AP name, location, zone, floor, coordinates,
  controller owner, interface, BSSID, band, channel, width, TX power, antenna
  gain, max clients, SSID bindings, neighbor APs, mesh role, steering intent,
  minimum RSSI, and load-balance weight.
- Deterministic channel planning for auto/manual/hybrid modes.
- Power planning bounded by global and per-band policy.
- Mesh planning with root AP/radio validation, same-band root selection,
  bridge VLAN, hop limit, backhaul SSID, and backhaul RSSI threshold.
- Client-steering policy generation by SSID with band preference, RSSI limits,
  load balancing, max clients per radio, reject-below-min-RSSI, and target
  radios.
- Controller action previews that keep live radio mutation behind explicit
  controller ownership and release certification evidence.
- Compliance checks for regulatory domain, topology, channel reuse, capacity,
  mesh roots, client steering, RRM/roaming linkage, and external certification.
- Durable event history in `rf_planning_lifecycle_events`.
- Admin API, OpenAPI, RBAC, system status, production readiness, support bundle,
  Admin UI, Makefile, and CI coverage.

## Standards And Vendor Scope

The software model is grounded in:

- IEEE 802.11-2020 radio operation
- IEEE 802.11k radio resource measurement
- IEEE 802.11v BSS transition and steering policy
- IEEE 802.11s mesh concepts
- IEEE 802.11ax and IEEE 802.11be planning considerations
- RFC 2865 and RFC 2866 for AAA correlation
- RFC 5176 where CoA/Disconnect is used after radio or steering policy changes

The vendor scope includes Cisco, Aruba/HPE, Ruckus, Extreme, Meraki, UniFi,
Cambium, Juniper Mist, Fortinet, MikroTik, OpenWiFi, and hostapd estates. The
software claims planning, validation, evidence, and API/UI governance; real
radio behavior is certified per release matrix.

## Configuration

RF planning is disabled by default. It may be used with `wireless.enabled:
false` for controller-owned AP estates, or with local hostapd ownership for lab
and appliance radio planning.

```yaml
wireless:
  enabled: false
  country_code: US
  ssids:
    - name: Aegis Corp
      auth_mode: wpa2-enterprise
  rf:
    enabled: true
    mode: monitor
    fail_closed: true
    channel_plan_mode: auto
    default_channel_width_mhz: 40
    min_power_dbm: 8
    max_power_dbm: 23
    target_cell_rssi: -67
    max_channel_reuse: 2
    max_clients_per_radio: 80
    bands:
      - name: 5ghz
        enabled: true
        channels: [36, 44, 149]
        channel_width_mhz: 40
        min_power_dbm: 8
        max_power_dbm: 23
        dfs_allowed: true
        max_clients_per_radio: 80
    mesh:
      enabled: true
      mode: monitor
      root_aps: [ap-lobby]
      backhaul_ssid: AegisMesh
      bridge_vlan: 30
      max_hops: 2
      min_backhaul_rssi: -67
      prefer_5ghz: true
    client_steering:
      enabled: true
      mode: monitor
      min_rssi: -72
      sticky_client_rssi: -78
      band_preference: 5ghz
      load_balance: true
      max_clients_per_radio: 80
      reject_below_min_rssi: true
    aps:
      - name: ap-lobby
        enabled: true
        zone: HQ
        floor: "1"
        radios:
          - name: radio-5g
            enabled: true
            band: 5ghz
            channel: 36
            channel_width_mhz: 40
            tx_power_dbm: 18
            max_clients: 80
            ssids: [Aegis Corp]
            mesh_enabled: true
            mesh_role: root
            client_steering: true
      - name: ap-hallway
        enabled: true
        zone: HQ
        floor: "1"
        radios:
          - name: radio-5g
            enabled: true
            band: 5ghz
            channel: 44
            channel_width_mhz: 40
            tx_power_dbm: 16
            max_clients: 80
            ssids: [Aegis Corp]
            mesh_enabled: true
            mesh_role: mesh
            client_steering: true
```

## API

```text
GET  /api/v1/system/rf-planning-lifecycle
POST /api/v1/system/rf-planning-lifecycle/preview
POST /api/v1/system/rf-planning-lifecycle/apply
GET  /api/v1/system/rf-planning-lifecycle/history
```

`GET` returns the current RF plan, radio inventory, channel plan, power plan,
mesh plan, steering policy, controller actions, compliance checks, software
completion state, and recent evidence.

`preview` validates and records evidence without changing radios or
controllers.

`apply` records a lifecycle checkpoint and runtime status. Physical controller
or AP mutation remains release certification until the adapter and firmware
scope is certified.

`history` returns durable event summaries and recent lifecycle events.

## Database

Schema v83 adds `rf_planning_lifecycle_events`. The table records:

- operation and status
- plan fingerprint
- country code, controller platform, and channel-plan mode
- AP, radio, band, channel, power, mesh-link, and steering-policy counters
- channel-conflict, capacity-warning, compliance, passed, warning, blocker, and
  external-requirement counters
- redacted summary/report JSON
- actor and timestamp

The event log is append/upsert safe by event ID and indexed for time, status,
fingerprint, controller platform, and country code.

## UI And Operations

Access Settings includes:

- `Preview RF Plan` and `Apply RF Plan`
- lifecycle status and release checklist link text
- AP/radio, channel, power, mesh, steering, and compliance cards
- blockers/warnings
- country, mode, and plan fingerprint evidence

System status exposes `wireless.rf_planning_lifecycle`; production readiness
uses `rf_planning_lifecycle`; support bundles include
`api/rf-planning-lifecycle.json` and
`api/rf-planning-lifecycle-history.json`.

## Security, HA, And Interoperability

- The planner does not store radio secrets or controller tokens.
- Controller actions are previews unless controller ownership and release
  certification explicitly allow live adapter mutation.
- Apply writes durable evidence and runtime status for HA peers and support
  bundles.
- The same preview can be replayed on active and standby nodes because the plan
  fingerprint is generated from normalized intent.
- Physical AP/controller interoperability remains release certification and must
  include firmware versions, packet/API captures, rollback proof, and customer
  scope.
