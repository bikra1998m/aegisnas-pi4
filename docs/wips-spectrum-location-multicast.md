# NAS-0080 Rogue, WIPS, Spectrum, Location, And Multicast

NAS-0080 adds the software lifecycle for enterprise wireless security and airtime governance. It covers rogue classification, WIPS detection families, spectrum watch plans, location privacy controls, multicast optimization intent, controller-action previews, compliance checks, durable event history, readiness, support bundles, and admin UI workflows.

This feature is software complete when the planner, API, UI, tests, and documentation are complete. Live radio containment, spectrum capture quality, location accuracy, multicast airtime improvement, controller firmware behavior, and customer-environment proof remain release certification work.

## Configuration

The feature is configured under `wireless.security`:

- `enabled`, `mode`, and `fail_closed` control lifecycle activation and enforcement posture.
- `rogue` defines trusted SSIDs/BSSIDs/OUIs, watched SSIDs, RSSI thresholds, quarantine role, and containment guardrails.
- `wips` selects detection families such as deauth/disassoc flood, evil twin, honeypot, ad-hoc, spoofing, flood, EAPOL attack, and PMF policy.
- `spectrum` defines watch thresholds for noise floor, channel utilization, interference, duty cycle, and sample interval.
- `location` defines presence/zone/coordinate mode, privacy mode, client identifier hashing, retention, coordinate export, and zones.
- `multicast` defines IGMP/MLD snooping, multicast-to-unicast, broadcast filtering, mDNS gatewaying, SSDP filtering, IPv6 multicast, and allowed groups.
- `sensors` declares dedicated WIPS/spectrum sensors. If omitted, the planner derives sensors from `wireless.rf.aps` or the local wireless interface.

## Lifecycle

The lifecycle is preview-first:

```text
GET  /api/v1/system/wireless-security-lifecycle
POST /api/v1/system/wireless-security-lifecycle/preview
POST /api/v1/system/wireless-security-lifecycle/apply
GET  /api/v1/system/wireless-security-lifecycle/history
```

Preview records an evidence event without live containment or controller mutation. Apply records a checkpoint and runtime status. A blocked apply returns HTTP 409 with the full report.

## Evidence

Schema v84 adds `wireless_security_lifecycle_events`. The ledger stores:

- operation and event status
- plan fingerprint
- mode and controller platform
- sensor, rogue, WIPS, spectrum, location, multicast, containment, privacy, compliance, warning, blocker, and external requirement counters
- summary JSON and full report JSON
- actor and timestamp

Production readiness exposes `wireless_security_lifecycle`. System status exposes `wireless.security_lifecycle`. Support bundles include:

- `api/wireless-security-lifecycle.json`
- `api/wireless-security-lifecycle-history.json`

## Standards And Interop Scope

The software model references IEEE 802.11, IEEE 802.11w, IEEE 802.11k/v, IEEE 802.1X, RFC 2865, RFC 2866, RFC 5176, RFC 4541, RFC 6762, and RFC 6763.

Vendor scope includes Cisco, Aruba, Ruckus, Extreme, Meraki, UniFi, Cambium, Juniper Mist, Fortinet, MikroTik, OpenWiFi, and hostapd style deployments. Vendor-specific live containment, spectrum sampling, location engines, multicast knobs, and controller mutation require release certification for the exact product and firmware.
