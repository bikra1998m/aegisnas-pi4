# 802.11r/k/v Roaming And Key Lifecycle

NAS-0075 completes the software implementation for local hostapd fast-roaming
intent. It renders IEEE 802.11r Fast Transition, IEEE 802.11k radio resource
measurement, IEEE 802.11v BSS transition, and PMF policy from AegisNAS
configuration while keeping FT key seed material behind secret references.

## Software Scope

Implemented software behavior:

- Global roaming policy and named per-SSID roaming profiles.
- WPA2/WPA3 Personal and Enterprise fast-transition key-management rendering.
- Mobility domain, R0 key lifetime, reassociation deadline, NAS identifier,
  R1 key holder, FT-over-DS, PMF-required, RRM, and BSS-transition controls.
- Neighbor AP inventory with BSSID, NAS identifier, R1 key holder, channel,
  operating class, preference, SSID scope, and secret reference.
- Deterministic per-neighbor `r0kh` and `r1kh` key derivation from configured
  secret references without storing or returning raw key seed material.
- Fail-closed validation for enforce-mode 802.11r neighbor key lifecycle.
- Redacted hostapd preview, SHA-256 fingerprints, blockers, warnings, and
  release certification scope.
- Audited preview, apply, status, and history APIs with event persistence.
- Admin API, OpenAPI, RBAC, production readiness, system status, support
  bundle, Access Settings UI, Makefile, CI, and automated tests.

## Standards And Attributes

Roaming itself is driven by IEEE WLAN standards and hostapd configuration. The
RADIUS/EAP attributes below are used to correlate roaming sessions, preserve
authorization state, and support accounting and CoA transitions:

- `EAP-Message`
- `Message-Authenticator`
- `Calling-Station-Id`
- `Called-Station-Id`
- `NAS-Identifier`
- `NAS-IP-Address`
- `Acct-Session-Id`
- `Acct-Multi-Session-Id`
- `Class`
- `Event-Timestamp`
- `Tunnel-Type`
- `Tunnel-Medium-Type`
- `Tunnel-Private-Group-Id`

Relevant standards:

- IEEE 802.11r, Fast BSS Transition
- IEEE 802.11k, Radio Resource Measurement
- IEEE 802.11v, Wireless Network Management
- IEEE 802.11w, Protected Management Frames
- IEEE 802.1X
- RFC 2865, RADIUS
- RFC 2866, RADIUS Accounting
- RFC 3748, EAP
- RFC 5176, Dynamic Authorization Extensions

Major enterprise Wi-Fi products from Cisco, Aruba, Ruckus, Extreme, Meraki,
UniFi, Juniper Mist, Fortinet, OpenWiFi, and hostapd expose equivalent roaming
or controller policy. Exact product and firmware interoperability remains
release certification evidence.

## API

Read the NAS-0075 report:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/wireless-roaming-lifecycle \
  | jq '.report.status, .report.summary, .report.ssids, .report.neighbors'
```

Record a preview event without writing hostapd state:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/wireless-roaming-lifecycle/preview \
  | jq '.event_id, .report.status, .report.blockers, .report.warnings'
```

Apply the generated hostapd roaming configuration:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/wireless-roaming-lifecycle/apply \
  | jq '.result.status, .event_id, .report.hostapd_config_sha256'
```

List lifecycle history:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/wireless-roaming-lifecycle/history \
  | jq '.summary, .events[0:10]'
```

Read-only and guest administrators can read and preview. `ops_admin` or
`super_admin` is required for apply.

## Configuration

Fast roaming requires WPA2/WPA3 personal or enterprise SSIDs and a secret
reference for FT key seed material:

```yaml
wireless:
  enabled: true
  interface: wlan0
  hostapd_config_path: /etc/hostapd/hostapd.conf
  roaming:
    enabled: true
    mode: enforce
    fail_closed: true
    ieee80211r: true
    ieee80211k: true
    ieee80211v: true
    mobility_domain: 4f57
    pmf_required: true
    nas_identifier: aegis-ap-1
    r1_key_holder: "001122334455"
    key_seed_ref: "env:AEGIS_FT_KEY_SEED"
    neighbor_aps:
      - name: ap-2
        bssid: "02:11:22:33:44:55"
        nas_identifier: aegis-ap-2
        r1_key_holder: "021122334455"
        ssids: ["Corp"]
        key_seed_ref: "env:AEGIS_FT_KEY_SEED"
    profiles:
      - name: corp-fast-roam
        enabled: true
        ieee80211r: true
        ieee80211k: true
        ieee80211v: true
        pmf_required: true
        neighbor_aps: ["ap-2"]
  ssids:
    - name: Corp
      auth_mode: wpa2-enterprise
      roaming_profile: corp-fast-roam
```

Rendered hostapd output includes fast-transition key management and neighbor
key holders:

```text
wpa_key_mgmt=WPA-EAP FT-EAP
mobility_domain=4f57
rrm_neighbor_report=1
bss_transition=1
r0kh=<neighbor> <nas-id> <derived-key>
r1kh=<neighbor> <r1kh-id> <derived-key>
```

API, UI, database, logs, and support bundles redact derived FT keys and never
expose the configured seed.

## Operations

Recommended rollout order:

1. Configure enterprise SSIDs, roaming profiles, neighbor APs, and secret refs.
2. Run `/api/v1/system/wireless-roaming-lifecycle/preview`.
3. Confirm `status=ready`, expected FT/RRM/BSS counts, no blockers, and
   redacted hostapd preview.
4. Apply `/api/v1/system/wireless-roaming-lifecycle/apply`.
5. Restart or publish hostapd on the appliance.
6. Capture external AP/client roaming, RADIUS accounting, and CoA evidence for
   the advertised product scope.

Support bundles include:

- `api/wireless-roaming-lifecycle.json`
- `api/wireless-roaming-lifecycle-history.json`

Production readiness includes `wireless_roaming_lifecycle`.
`/api/v1/system/status` reports the same state under
`wireless.roaming_lifecycle`.

## Release Certification Checklist

External validation is tracked in
`nas-0075-release-certification-checklist.md`. Real client roam behavior,
controller/AP firmware validation, packet captures, HA failover, scale,
long-duration soak, security audit, production deployment, and customer proof
are release certification activities. They do not block NAS-0075 software
completion.
