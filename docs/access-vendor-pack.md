# NAS-0067 Cambium, TP-Link, and D-Link Access Pack

NAS-0067 software-certifies the access-vendor pack for Cambium, TP-Link Omada,
and D-Link/Nuclias dictionary coverage. The pack covers every Cambium, TPLink,
and Dlink row in the pinned FreeRADIUS 3.2.8 VSA registry and maps each row to
AegisNAS vendor-neutral role, VLAN, ACL, bandwidth, quota, portal, accounting,
posture, and CoA semantics.

The pack covers 49 software-certified rows:

- Cambium: 31 rows for cnMaestro/ePMP/PMP role, VLAN, priority, rate, traffic
  quota, walled garden, authorize-class TLV, and traffic-class accounting TLV.
- TP-Link: 9 rows for Omada receive/transmit rate limits, site, controller
  group, redirect URL, portal access status, user-command evidence, and
  authentication-key redacted evidence.
- D-Link: 9 rows for user level, ingress/egress bandwidth, 802.1p priority,
  VLAN name/ID, ACL profile, ACL rule, and ACL script.

## Software Behavior

The implementation provides:

- generated runtime registry mappings for every Cambium, TPLink, and Dlink row
- inbound packet normalization into vendor-neutral policy semantics
- reply rendering for Cambium role, VLAN, rate, quota, and walled-garden fields
- reply rendering for TP-Link Omada rate, site, group, redirect, and portal
  status fields
- reply rendering for D-Link exact dictionary names for user level, bandwidth,
  VLAN, ACL profile, and dynamic ACL rules
- typed TLV evidence for Cambium authorize-class and traffic-class containers
- redacted typed evidence for TP-Link authentication-key octets
- durable certification evidence in `access_vendor_pack_events`
- admin API, OpenAPI, RBAC, production readiness, system status, support bundle,
  admin UI, Makefile, and CI integration

Rows that require controller or firmware behavior are software-certified as
typed, bounded evidence with an explicit release certification boundary.
AegisNAS exposes the attribute, source row, codec, semantic family, claim state,
fingerprint, and required external proof without publishing uncertified hardware
claims.

## API

```text
GET  /api/v1/system/access-vendor-pack
POST /api/v1/system/access-vendor-pack/record
GET  /api/v1/system/access-vendor-pack/history
```

`GET` returns the generated report, vendor rollups, capability rollups, product
scopes, grammar records, per-attribute records, release scope, and recent
evidence. `record` persists the current source hash, fingerprint, counts,
summary JSON, full report JSON, actor, and timestamp. `history` lists recorded,
blocked, and failed evidence events.

The same status is exposed in:

- `/api/v1/system/status` under `radius.access_vendor_pack`
- `/api/v1/system/production-readiness` as `access_vendor_pack`
- support bundles as `api/access-vendor-pack.json`
- support bundles as `api/access-vendor-pack-history.json`
- the Vendor Compatibility admin UI

## Packet Behavior

Cambium packets map as follows:

| Attribute Family | Semantic |
| --- | --- |
| `Cambium-Auth-Role`, `Cambium-ePMP-UserLevel` | Role through numeric role mappings |
| `Cambium-ePMP-Data-VLAN-Id`, management and multicast VLAN fields | VLAN intent |
| `Cambium-ePMP-Max-Burst-Downlink-Rate`, `Cambium-ePMP-Max-Burst-Uplink-Rate` | Download and upload bandwidth in kbps |
| `Cambium-Traffic-Quota-Limit-*` | Session quota and accounting evidence |
| `Cambium-Walled-Garden-State` | Quarantine and portal state |
| `Cambium-Authorize-Classes`, `Cambium-Traffic-Classes-Acct` | Typed TLV evidence |

TP-Link packets map as follows:

| Attribute | Semantic |
| --- | --- |
| `TPLink-Xmit-limit`, `TPLink-Recv-limit` | Download and upload bandwidth in kbps |
| `TPLink-Site` | Tenant or site context |
| `TPLink-Omada` | Device group or controller group |
| `TPLink-Redirect-Url` | Portal profile URL |
| `TPLink-Portal-Access-Status` | Portal profile through numeric status mappings |
| `TPLink-Authentication-FindKey`, `TPLink-Authentication-FoundKey` | Redacted authentication-key evidence |
| `TPLink-User-Command` | Command authorization evidence |

D-Link packets map as follows:

| Attribute | Semantic |
| --- | --- |
| `Dlink-User-Level` | Role through numeric role mappings |
| `Dlink-Ingress-Bandwidth-Assignment`, `Dlink-Egress-Bandwidth-Assignment` | Upload and download bandwidth in kbps |
| `Dlink-1p-Priority` | Bandwidth profile or priority class |
| `Dlink-VLAN-Name`, `Dlink-VLAN-ID` | VLAN name context and numeric VLAN assignment |
| `Dlink-ACL-Profile` | ACL profile reference |
| `Dlink-ACL-Rule`, `Dlink-ACL-Script` | Dynamic ACL rule/script intent |

## Operator Workflow

1. Confirm the active dictionary release profile is the pinned FreeRADIUS 3.2.8
   registry.
2. Inspect `/api/v1/system/access-vendor-pack` and confirm software completion
   is 100%.
3. Configure numeric role mappings for Cambium and D-Link where the target
   firmware uses integer privilege levels.
4. Configure TP-Link portal status mappings where Omada portal workflows require
   numeric state values.
5. Configure Cambium quota mappings when roles need
   `Cambium-Traffic-Quota-Limit-Total` replies.
6. Record software evidence with `/api/v1/system/access-vendor-pack/record`.
7. Export a support bundle and retain the two access-vendor pack JSON files.
8. Execute `docs/nas-0067-release-certification-checklist.md` before publishing
   product, firmware, hardware, controller, HA, performance, or
   customer-certified claims.

## Verification

Run the focused software certification target:

```bash
make test-access-vendor-pack
```

The target validates the report, registry contract, vendor pack catalog,
dictionary release profile, Cambium/TP-Link/D-Link packet decoding, D-Link ACL
compiler output, Cambium quota rendering, database event lifecycle, admin API,
OpenAPI, RBAC, readiness, support bundle capture, and admin UI build.

## Release Boundary

Software implementation is complete when the automated checks pass and the
NAS-0067 report validates all 49 rows with zero software blockers. External
Cambium cnMaestro/ePMP/PMP, TP-Link Omada, D-Link/Nuclias, access point,
switch, gateway, production Linux FreeRADIUS, HA, performance, soak, security,
deployment, and customer acceptance proof is release certification evidence and
does not keep NAS-0067 open for engineering.
