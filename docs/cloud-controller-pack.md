# NAS-0066 Meraki, UniFi, and OpenWiFi Cloud Pack

NAS-0066 software-certifies the cloud-controller access pack for Cisco Meraki,
Ubiquiti/UniFi, and TIP OpenWiFi. The pack covers the Meraki and OpenWiFi rows
from the pinned FreeRADIUS 3.2.8 VSA registry plus the AegisNAS-runtime UBNT
rate attributes used by UniFi deployments.

The pack covers seven software-certified rows:

- Meraki: 4 rows for device name, Dashboard network name, AP name, and AP tags.
- OpenWiFi: 1 row for AP MAC address accounting identity.
- Ubiquiti/UniFi: 2 AegisNAS runtime rows for downstream and upstream UBNT data
  rate attributes.

FreeRADIUS 3.2.8 does not include a Ubiquiti namespace in the parsed dictionary
share tree. AegisNAS therefore treats UBNT rate attributes as governed runtime
compatibility extensions. Authoritative external dictionary intake for broader
UniFi VSAs is handled by the NAS-0073 external vendor intake workflow.

## Software Behavior

The implementation provides:

- typed packet decoding for all four Meraki telemetry VSAs
- OpenWiFi AP MAC address decoding through the generated attribute registry
- UBNT downstream and upstream rate parsing from integer bps into neutral kbps
- UBNT downstream and upstream rate rendering from neutral kbps into integer bps
- controller product scopes for Meraki Dashboard, UniFi Network, and TIP
  OpenWiFi OWGW/uCentral integrations
- explicit boundaries for Meraki group policy, splash, Systems Manager posture,
  switch, appliance, VPN, and RF behavior
- explicit boundaries for UniFi gateway, switch, hotspot, and external UBNT
  dictionary intake
- API secret redaction and controller health scope through the shared native
  controller adapter framework
- durable certification evidence in `cloud_controller_pack_events`
- admin API, OpenAPI, RBAC, production readiness, system status, support bundle,
  admin UI, Makefile, and CI integration

Rows without a RADIUS enforcement primitive are software-certified as typed
cloud context. AegisNAS exposes the attribute, source row, codec, semantic
family, claim state, fingerprint, and release proof boundary without silently
claiming device behavior that requires live controller validation.

## API

```text
GET  /api/v1/system/cloud-controller-pack
POST /api/v1/system/cloud-controller-pack/record
GET  /api/v1/system/cloud-controller-pack/history
```

`GET` returns the generated report, vendor rollups, capability rollups, product
scopes, grammar records, per-attribute records, release scope, and recent
evidence. `record` persists the current source hash, fingerprint, counts,
summary JSON, full report JSON, actor, and timestamp. `history` lists recorded,
blocked, and failed evidence events.

The same status is exposed in:

- `/api/v1/system/status` under `radius.cloud_controller_pack`
- `/api/v1/system/production-readiness` as `cloud_controller_pack`
- support bundles as `api/cloud-controller-pack.json`
- support bundles as `api/cloud-controller-pack-history.json`
- the Vendor Compatibility admin UI

## Packet Behavior

Meraki accounting and inbound packets map as follows:

| Attribute | Semantic |
| --- | --- |
| `Meraki-Device-Name` | Device group or NAS context |
| `Meraki-Network-Name` | Tenant or Dashboard network context |
| `Meraki-Ap-Name` | Accounting identity |
| `Meraki-Ap-Tags` | Device posture or tag evidence |

OpenWiFi accounting and inbound packets map as follows:

| Attribute | Semantic |
| --- | --- |
| `OpenWiFi-AP-MAC-Address` | Accounting identity |

UniFi UBNT runtime packets map as follows:

| Attribute | Direction | Semantic |
| --- | --- | --- |
| `UBNT-Data-Rate-DL` | Inbound and reply | Download bandwidth, integer bps |
| `UBNT-Data-Rate-UL` | Inbound and reply | Upload bandwidth, integer bps |

## Operator Workflow

1. Confirm the active dictionary release profile is the pinned FreeRADIUS 3.2.8
   registry.
2. Inspect `/api/v1/system/cloud-controller-pack` and confirm software
   completion is 100%.
3. Generate reply previews for Meraki, UniFi, and OpenWiFi deployment profiles.
4. Record software evidence with
   `/api/v1/system/cloud-controller-pack/record`.
5. Export a support bundle and retain the two cloud-controller pack JSON files.
6. Execute `docs/nas-0066-release-certification-checklist.md` before publishing
   product, firmware, hardware, cloud-controller, HA, performance, or
   customer-certified claims.

## Verification

Run the focused software certification target:

```bash
make test-cloud-controller-pack
```

The target validates the report, registry contract, Meraki/OpenWiFi/UBNT packet
decoding, UBNT reply rendering, database event lifecycle, admin API, OpenAPI,
RBAC, readiness, support bundle capture, and admin UI build.

## Release Boundary

Software implementation is complete when the automated checks pass and the
NAS-0066 report validates all seven rows with zero software blockers. External
Meraki Dashboard, UniFi Network, OpenWiFi OWGW/uCentral, access point, gateway,
switch, appliance, production Linux FreeRADIUS, HA, performance, soak,
security, deployment, and customer acceptance proof is release certification
evidence and does not keep NAS-0066 open for engineering.
