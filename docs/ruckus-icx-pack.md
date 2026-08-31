# NAS-0064 Ruckus and ICX Pack

NAS-0064 software-certifies the Ruckus and Foundry dictionary rows from the
pinned FreeRADIUS 3.2.8 VSA registry. Foundry is tracked here as the Ruckus ICX
switch family because those dictionary rows represent the ICX/FastIron command,
ACL, 802.1X, VLAN/QoS, CoA, role-template, and voice-policy surface.

The pack covers 97 dictionary rows:

- Ruckus: SmartZone, ZoneDirector, Unleashed, and Ruckus One role groups, VLAN
  and VLAN pool hints, WLAN and SSID context, WISPr redirect policies, guest
  portal tokens, FlexAuth key-value policy, DPSK/PPSK credential evidence, QoS
  and traffic class hints, subscriber quota, NAT pool, mobile-core identifiers,
  accounting context, posture, zone, cluster, domain, and SCI resource fields.
- Foundry/ICX: administrative privilege, command authorization, command
  exception flags, access-list assignment, MAC authentication and 802.1X lookup
  controls, MAC-based VLAN/QoS, INM role/AOR fields, CoA commands, service
  identity role templates, and voice-phone policy hints.

## Software Behavior

The implementation provides:

- typed registry annotations for every pinned Ruckus and Foundry row
- native inbound normalization for role, VLAN, VLAN pool, ACL, dynamic ACL,
  guest portal, QoS, quota, accounting identity, device context, posture, tenant,
  address pool, IPv4 address, mobile-core context, CoA, command authorization,
  session timeout, and redacted secret semantics
- outbound reply rendering for Ruckus operational attributes and Foundry/ICX
  switch authorization attributes
- `Ruckus-FlexAuth-AVP` parsing with bounded key-value grammar and invalid token
  rejection
- IPv4 VSA decoding for Ruckus local client, SGSN, and AAA IP fields
- quota decoding through `Ruckus-Max-DL-UL-Quota`
- DPSK, EAPOL, triplet, mobile subscriber, and sensitive policy value redaction
- durable certification evidence in `ruckus_icx_pack_events`
- admin API, OpenAPI, RBAC, production readiness, system status, support bundle,
  admin UI, Makefile, and CI integration

Rows without a safe neutral behavior are software-certified as typed
pass-through or typed evidence. AegisNAS exposes the attribute, source row,
codec, semantic family, claim state, fingerprint, and release proof boundary
without silently enforcing behavior that requires real Ruckus or ICX validation.

## API

```text
GET  /api/v1/system/ruckus-icx-pack
POST /api/v1/system/ruckus-icx-pack/record
GET  /api/v1/system/ruckus-icx-pack/history
```

`GET` returns the generated report, vendor rollups, capability rollups, product
scopes, grammar records, per-attribute records, release scope, and recent
evidence. `record` persists the current source hash, fingerprint, counts,
summary JSON, full report JSON, actor, and timestamp. `history` lists recorded,
blocked, and failed evidence events.

The same status is exposed in:

- `/api/v1/system/status` under `radius.ruckus_icx_pack`
- `/api/v1/system/production-readiness` as `ruckus_icx_pack`
- support bundles as `api/ruckus-icx-pack.json`
- support bundles as `api/ruckus-icx-pack-history.json`
- the Vendor Compatibility admin UI

## Operator Workflow

1. Confirm the active dictionary release profile is the pinned FreeRADIUS 3.2.8
   registry.
2. Inspect `/api/v1/system/ruckus-icx-pack` and confirm software completion is
   100%.
3. Generate reply previews for the target Ruckus wireless or ICX switch
   deployment profile.
4. Record software evidence with `/api/v1/system/ruckus-icx-pack/record`.
5. Export a support bundle and retain the two Ruckus/ICX pack JSON files.
6. Execute `docs/nas-0064-release-certification-checklist.md` before publishing
   product, firmware, hardware, HA, performance, or customer-certified claims.

## Verification

Run the focused software certification target:

```bash
make test-ruckus-icx-pack
```

The target validates the report, registry contract, packet parser, reply
renderer, database event lifecycle, admin API, OpenAPI, RBAC, readiness,
support bundle capture, and admin UI build.

## Release Boundary

Software implementation is complete when the automated checks pass and the
NAS-0064 report validates all 97 pinned rows with zero software blockers.
External Ruckus controller, ICX/FastIron switch, production Linux FreeRADIUS, HA,
performance, soak, security, deployment, and customer acceptance proof is release
certification evidence and does not keep NAS-0064 open for engineering.
