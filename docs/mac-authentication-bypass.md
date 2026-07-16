# MAC Authentication Bypass

NAS-0017 implements MAC Authentication Bypass for access devices that need a controlled fallback when 802.1X is unavailable.

MAB is useful for printers, cameras, badge readers, industrial controllers, and other endpoints that cannot run an EAP supplicant. The NAS sends a RADIUS Access-Request where the MAC address appears in `User-Name`, `Calling-Station-Id`, or both. AegisNAS normalizes the MAC, evaluates endpoint state, links device profile posture when available, and renders deterministic FreeRADIUS `files/authorize` entries for approved or quarantined endpoints.

## Standards And Vendor Scope

MAB uses standard RADIUS Access-Request and Access-Accept/Reject behavior from RFC 2865. The common attributes are:

- `User-Name`
- `User-Password`
- `Calling-Station-Id`
- `Called-Station-Id`
- `NAS-Identifier`
- `NAS-IP-Address`
- `NAS-Port`
- `NAS-Port-Type`
- `Service-Type`
- `Filter-Id`
- VLAN tunnel attributes from RFC 2868

Cisco, Aruba/HPE, Juniper, Ruckus, Extreme, HP, MikroTik, UniFi, Fortinet, Cambium, and other access vendors support MAB-style MAC fallback. Vendor-specific replies are still emitted through the existing compatibility packs, including role, VLAN, ACL, bandwidth, quarantine, and portal hints where those packs already define them.

## Configuration

```yaml
mab:
  enabled: true
  mode: enforce
  fail_closed: true
  unknown_endpoint_policy: deny
  default_role: employee
  guest_role: guest
  quarantine_role: quarantine
  allowed_nas_port_types: [ethernet, wireless-802.11, wireless80211]
  mac_formats: [colon, hyphen, plain, cisco-dot]
  password_policy: accept_known_mac
  profiling_link_enabled: true
  endpoint_inventory_fallback: true
  revalidate_interval_seconds: 300
  cache_ttl_seconds: 300
  audit_enabled: true
  retention_limit: 6000
```

`unknown_endpoint_policy` may be `deny`, `guest`, `quarantine`, or `fail_open`. Keep `fail_open` out of production unless a documented outage procedure requires it.

`mode: monitor` records and previews decisions while allowing candidates that enforce mode would reject. `mode: enforce` applies the endpoint state machine.

## Endpoint State

MAB endpoints live in `mab_endpoints`:

- `approved`: accepted with endpoint role and optional VLAN, bandwidth, ACL, tenant, device group, and posture overrides.
- `quarantined`: accepted with quarantine policy.
- `pending`: rejected in enforce mode and allowed only in monitor mode.
- `denied`: rejected in enforce mode.
- `expired`: rejected in enforce mode.

Unknown endpoints follow `unknown_endpoint_policy`. When profiling linkage is enabled, high-risk or non-compliant unknown endpoints are quarantined before guest or fail-open policy is considered.

## API

```text
GET    /api/v1/system/mab
GET    /api/v1/system/mab/endpoints
POST   /api/v1/system/mab/endpoints
PUT    /api/v1/system/mab/endpoints/{mac}
DELETE /api/v1/system/mab/endpoints/{mac}
POST   /api/v1/system/mab/evaluate
```

Endpoint writes require `ops_admin` or `super_admin`. Read-only roles can inspect state. Evaluation requires `ops_admin` or `super_admin`.

## FreeRADIUS Generation

Approved and quarantined endpoints are rendered into `files/authorize` with `Auth-Type := Accept`. AegisNAS emits configured MAC variants so devices using colon, hyphen, plain, or Cisco dotted MAC usernames match the same endpoint record.

The reply payload is built through the existing role and vendor-pack renderer, so MAB can return:

- standard VLAN tunnel attributes
- `Filter-Id`
- session and idle timeouts
- bandwidth hints
- ACL policy exports
- AegisNAS product VSAs
- enabled vendor compatibility pack attributes

## Operational Checks

Use these checks before enabling MAB on a live SSID or switch port:

1. Keep `mab.mode: enforce` and `mab.fail_closed: true`.
2. Verify `GET /api/v1/system/mab` reports ready or an intentional degraded state.
3. Create approved or quarantined endpoints through the API or admin UI.
4. Run `POST /api/v1/system/mab/evaluate` with a sample access request.
5. Run `aegis-radius gen-config` and inspect the generated MAB entries.
6. Apply RADIUS config only after production readiness has no MAB blockers.
7. Keep device-profile collection enabled when quarantine automation depends on posture.

## Release Certification Checklist

Software implementation is complete when automated tests, generated config, API, UI, migrations, and docs pass. Real AP/switch/controller testing, packet captures, HA failover drills, scale benchmarks, soak testing, and customer acceptance belong to `nas-0017-release-certification-checklist.md`.
