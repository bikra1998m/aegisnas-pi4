# Passpoint And Hotspot 2.0 Lifecycle

NAS-0076 adds a production software lifecycle for local hostapd Passpoint and
Hotspot 2.0 configuration. It turns a vendor-neutral AegisNAS profile into
validated hostapd `interworking` and `hs20` settings, records preview/apply
evidence, exposes API/UI status, and keeps real AP/client/carrier validation in
release certification.

## Problem

Enterprise and hotspot operators need Wi-Fi clients to discover the correct
network before association. Passpoint and Hotspot 2.0 advertise venue,
operator, domain, roaming consortium, NAI realm, 3GPP cellular, WAN metrics,
connection capability, and OSU metadata through ANQP. Without a lifecycle,
operators either hand-edit hostapd or cannot prove what metadata was published.

## Scope

Implemented software behavior:

- global and per-profile Passpoint configuration under `wireless.passpoint`
- per-SSID profile binding through `wireless.ssids[].passpoint_profile`
- 802.11u interworking and Hotspot 2.0 hostapd rendering
- ANQP fields for domain names, roaming consortium OIs, NAI realms, 3GPP PLMNs,
  WAN metrics, connection capability, operator friendly names, venue names, and
  OSU provider metadata
- fail-closed validation for enterprise Passpoint profiles
- redacted hostapd preview and SHA-256 evidence
- preview, apply, history, status, readiness, OpenAPI, RBAC, support bundle, and
  admin UI integration
- durable `passpoint_lifecycle_events` history with summary counters

Release certification scope:

- Wi-Fi Alliance Passpoint/Hotspot 2.0 certification
- carrier roaming agreement and settlement validation
- production FreeRADIUS Linux interoperability
- real AP/client packet captures
- SIM/AKA carrier credential interoperability
- HA failover, performance, soak, security audit, deployment, and customer
  acceptance proof

## Standards And Attributes

The lifecycle is grounded in:

- IEEE 802.11u and Wi-Fi Alliance Hotspot 2.0 / Passpoint
- IEEE 802.1X and EAP
- RFC 2865, RFC 2866, RFC 3748, RFC 4186, RFC 4187, RFC 5448, RFC 5176

RADIUS and hotspot attributes that commonly participate in deployments include:

- `EAP-Message`
- `Message-Authenticator`
- `Operator-Name`
- `Chargeable-User-Identity`
- `Tunnel-Type`, `Tunnel-Medium-Type`, `Tunnel-Private-Group-Id`
- WISPr bandwidth/session attributes
- ChilliSpot and Nomadix hotspot attributes when a portal flow is used

NAS-0076 does not claim that all roaming-settlement, carrier clearinghouse, or
vendor controller APIs are certified. Those claims require the release
certification checklist.

## Configuration

Passpoint is disabled by default. Enable it only on physical appliances or lab
systems where hostapd owns the SSID.

```yaml
wireless:
  enabled: true
  passpoint:
    enabled: true
    mode: enforce
    fail_closed: true
    interworking: true
    hs20: true
    default_profile: corp-passpoint
    domain_names: ["corp.example.test"]
    roaming_consortium_ois: ["112233"]
    operator_friendly_names:
      - lang: eng
        text: "AegisNAS"
    nai_realms:
      - realm: "corp.example.test"
        eap_methods: ["tls", "ttls"]
    profiles:
      - name: corp-passpoint
        enabled: true
        mode: enforce
        interworking: true
        hs20: true
        domain_names: ["corp.example.test"]
        roaming_consortium_ois: ["112233"]
        nai_realms:
          - realm: "corp.example.test"
            eap_methods: ["tls", "ttls"]
  ssids:
    - name: Aegis Corp
      auth_mode: wpa3-enterprise
      identity_source: radius-upstream
      passpoint_profile: corp-passpoint
```

Fail-closed enforcement requires at least one active Passpoint SSID, domain
name, NAI realm, and operator friendly name for Hotspot 2.0 profiles. Personal
WPA auth modes are rejected because Passpoint discovery should be paired with
open/captive or enterprise authentication.

## API

```text
GET  /api/v1/system/passpoint-lifecycle
POST /api/v1/system/passpoint-lifecycle/preview
POST /api/v1/system/passpoint-lifecycle/apply
GET  /api/v1/system/passpoint-lifecycle/history
```

`GET` returns the effective global/profile/SSID state, generated hostapd
preview, diagnostics, software completion state, and recent evidence.

`preview` validates and records evidence without changing host files.

`apply` validates the same plan, writes the hostapd config through the shared
wireless writer, and records the apply event. Blocked or failed attempts are
also recorded for incident analysis.

`history` returns durable event summaries and recent lifecycle events from the
database.

## Database

Schema v80 adds `passpoint_lifecycle_events`. The table records:

- operation and status
- config path and hostapd config SHA-256
- deterministic plan fingerprint
- SSID, Passpoint, interworking, HS2.0, OSU, domain, OI, NAI realm, cellular,
  connection capability, and diagnostic counters
- redacted summary/report JSON
- actor and timestamp

The event log is append/upsert safe by event ID and has indexes for time,
status, fingerprint, and config path.

## UI And Operations

Access Settings includes:

- global Passpoint and Hotspot 2.0 controls
- profile editor
- per-SSID Passpoint profile selector
- lifecycle summary cards
- blockers/warnings
- active SSID and profile evidence
- redacted hostapd preview
- `Preview Passpoint` and `Apply Passpoint` actions

System status exposes `wireless.passpoint_lifecycle`; production readiness uses
`wireless_passpoint_lifecycle`; support bundles include
`api/passpoint-lifecycle.json` and `api/passpoint-lifecycle-history.json`.

## Security And HA

Secrets are not stored in Passpoint profile fields. Generated hostapd previews
are redacted before API, UI, support bundle, and lifecycle-history exposure.
Apply is RBAC-protected for operations administrators. Preview is allowed to
read-only, guest admin, and ops admin roles for safe review.

The lifecycle records enough evidence for active/standby comparison. Real
hostapd restart orchestration, AP radio behavior, and failover proof remain
release certification items because they depend on hardware and deployment
topology.

## Test Evidence

Automated software coverage includes:

- config validation and effective profile resolution
- hostapd Passpoint/HS2.0 render tests
- lifecycle preview/apply/redaction tests
- database event record/list/summary tests
- admin API, OpenAPI, RBAC, readiness, system status, and support bundle tests
- admin UI build and mocked browser workflow
- CI target `make test-passpoint-lifecycle`

External lab evidence is tracked in
`nas-0076-release-certification-checklist.md`.
