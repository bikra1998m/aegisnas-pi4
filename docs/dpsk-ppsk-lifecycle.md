# DPSK And PPSK Lifecycle

NAS-0077 adds a production software lifecycle for local hostapd DPSK/PPSK
configuration. It turns vendor-neutral per-device key intent into a validated
hostapd `wpa_psk_file`, records preview/apply evidence, exposes API/UI status,
and keeps controller/AP interoperability proof in release certification.

## Problem

Shared WPA personal keys are hard to rotate, impossible to attribute cleanly,
and unsafe for enterprise or managed guest environments. Dynamic PSK and
private PSK deployments solve this by assigning a unique key to a device,
owner, tenant, or group while still using WPA2 personal association on devices
that cannot run 802.1X.

Without a lifecycle, operators hand-edit controller/AP key lists, lose history,
or expose secrets in logs and support bundles. NAS-0077 provides safe
configuration, validation, rendering, evidence, and rollback data for the
software side of local-radio PPSK.

## Scope

Implemented software behavior:

- global PPSK settings under `wireless.ppsk`
- per-profile PPSK policy with fail-closed mode, group scope, VLAN, role,
  bandwidth, max-device, and controller-sync intent
- per-group metadata for tenant, VLAN, role, bandwidth, max-device, and session
  limits
- per-credential MAC binding, owner/device metadata, active/staged/revoked
  state, secret refs, next-secret refs, rotation windows, VLAN, role, tenant,
  and bandwidth fields
- per-SSID profile binding through `wireless.ssids[].ppsk_profile`
- hostapd `wpa_psk_file` rendering for active WPA2 personal PPSK SSIDs
- redacted preview and SHA-256 evidence for both hostapd config and PSK file
- preview, apply, history, status, readiness, OpenAPI, RBAC, support bundle, and
  admin UI integration
- durable `ppsk_lifecycle_events` history with summary counters

Release certification scope:

- real Ruckus DPSK, Aruba MPSK, Cisco/UniFi/Cambium private-PSK behavior
- controller API push/pull and drift reconciliation in production controller
  estates
- production FreeRADIUS Linux interoperability
- real AP/client packet captures
- HA failover, performance, soak, security audit, deployment, and customer
  acceptance proof

## Standards And Attributes

The lifecycle is grounded in:

- IEEE 802.11i / IEEE 802.11-2020 WPA personal key handling
- RFC 2865 and RFC 2866 for RADIUS authorization/accounting correlation
- RFC 5176 where CoA/Disconnect is used after revocation or VLAN/role changes

RADIUS and vendor attributes commonly involved in DPSK/PPSK deployments include:

- `Tunnel-Type`, `Tunnel-Medium-Type`, `Tunnel-Private-Group-Id`
- `Filter-Id`, `Class`, `Session-Timeout`, `Idle-Timeout`
- Cisco AVPair/downloadable ACL attributes for role and ACL intent
- Aruba role/filter attributes such as `Aruba-User-Role`
- Ruckus DPSK/FlexAuth role/group attributes
- UniFi and Cambium vendor attributes for WLAN, group, and VLAN policy

NAS-0077 does not claim that every controller API has been certified. Local
hostapd rendering, evidence, validation, and management APIs are complete; real
controller/AP behavior is tracked in the release certification checklist.

## Configuration

PPSK is disabled by default. Enable it only on a lab or appliance where hostapd
owns a WPA2 personal SSID and secrets are available through configured secret
references.

```yaml
wireless:
  enabled: true
  ppsk:
    enabled: true
    mode: enforce
    fail_closed: true
    default_profile: staff-ppsk
    psk_file_path: /etc/hostapd/aegisnas-ppsk.psk
    rotation_mode: active
    min_passphrase_length: 12
    profiles:
      - name: staff-ppsk
        enabled: true
        mode: enforce
        fail_closed: true
        groups: ["staff"]
        default_vlan: 20
        role: employee
        bandwidth_profile: corp-standard
    groups:
      - name: staff
        enabled: true
        vlan: 20
        role: employee
    credentials:
      - id: laptop-1
        enabled: true
        status: active
        mac: "02:11:22:33:44:55"
        profile: staff-ppsk
        groups: ["staff"]
        secret_ref: "env:AEGIS_PPSK_LAPTOP_1"
  ssids:
    - name: Aegis Staff PPSK
      auth_mode: wpa2-personal
      ppsk_profile: staff-ppsk
```

Fail-closed enforcement requires at least one active credential with a MAC and
secret ref for each active PPSK SSID. WPA3 personal is not rendered by the local
hostapd PPSK writer in this feature because hostapd per-station PSK files are
validated for WPA2 personal scope here.

## API

```text
GET  /api/v1/system/ppsk-lifecycle
POST /api/v1/system/ppsk-lifecycle/preview
POST /api/v1/system/ppsk-lifecycle/apply
GET  /api/v1/system/ppsk-lifecycle/history
```

`GET` returns the effective global/profile/group/credential/SSID state,
generated hostapd preview, redacted PSK-file preview, diagnostics, software
completion state, and recent evidence.

`preview` validates and records evidence without changing host files.

`apply` validates the same plan, writes the managed PPSK file with mode `0600`,
writes the hostapd config through the shared wireless writer, and records the
apply event. Blocked or failed attempts are also recorded for incident analysis.

`history` returns durable event summaries and recent lifecycle events from the
database.

## Database

Schema v81 adds `ppsk_lifecycle_events`. The table records:

- operation and status
- hostapd config path and PPSK file path
- hostapd and PPSK file SHA-256 fingerprints
- deterministic plan fingerprint
- SSID, PPSK SSID, profile, group, credential, active/staged/revoked/expired,
  controller-sync, and diagnostic counters
- redacted summary/report JSON
- actor and timestamp

The event log is append/upsert safe by event ID and has indexes for time,
status, fingerprint, config path, and PSK file path.

## UI And Operations

Access Settings includes:

- global DPSK/PPSK controls
- profile editor
- group editor
- credential editor
- per-SSID PPSK profile selector
- lifecycle summary cards
- blockers/warnings
- active SSID and credential evidence
- redacted hostapd and PSK-file previews
- `Preview PPSK` and `Apply PPSK` actions

System status exposes `wireless.ppsk_lifecycle`; production readiness uses
`wireless_ppsk_lifecycle`; support bundles include `api/ppsk-lifecycle.json`
and `api/ppsk-lifecycle-history.json`.

## Security And HA

PPSK secrets are referenced through secret refs and are resolved only during
preview/apply validation and PPSK file generation. API responses, UI panels,
support bundles, and lifecycle history store fingerprints and redacted previews,
not raw PSK values. The managed hostapd PPSK file is written with `0600`
permissions.

Apply is RBAC-protected for operations administrators. Preview is allowed to
read-only, guest admin, and ops admin roles for safe review.

The lifecycle records enough fingerprints and counters for active/standby
comparison. Real AP/controller propagation, roaming behavior, and failover proof
remain release certification items because they depend on hardware and
deployment topology.

## Test Evidence

Automated software coverage includes:

- config validation and effective profile/group/credential resolution
- hostapd PPSK config and PSK-file render tests
- lifecycle preview/apply/redaction tests
- database event record/list/summary tests
- admin API, OpenAPI, RBAC, readiness, system status, and support bundle tests
- admin UI build and mocked browser workflow
- CI target `make test-ppsk-lifecycle`

External lab evidence is tracked in
`nas-0077-release-certification-checklist.md`.
