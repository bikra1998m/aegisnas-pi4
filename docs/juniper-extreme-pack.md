# NAS-0063 Juniper, ERX, Extreme, and Mist Pack

NAS-0063 software-certifies the Juniper, ERX/E-Series, and Extreme dictionary
rows from the pinned FreeRADIUS 3.2.8 VSA registry and tracks Juniper Mist as a
Juniper controller/product scope. Mist has no separate VSA rows in the pinned
FreeRADIUS 3.2.8 corpus, so Mist release proof is handled as product-scope
evidence rather than a fabricated dictionary namespace.

The pack covers 260 dictionary rows:

- Juniper: Junos administrative roles, command authorization hints, firewall
  filters, local groups/interfaces, VLAN, CWA redirect, DHCP option evidence,
  CoS/policer settings, and `Juniper-AV-Pair` policy tokens.
- ERX: virtual routers, address pools, DNS, ingress/egress policies, PPPoE,
  service activation/deactivation, service quotas and timers, IPv6 VR/pools/RA,
  DHCPv6 relay, service sets, PCEF rules, data-rate attributes, bulk CoA
  identifiers, and accounting request reasons.
- Extreme: CLI authorization, shell command hints, netlogin VLAN and portal
  hints, extended VLAN syntax, security profile, user location, and VM context.
- Mist: controller/API product scope for enterprise WLAN synchronization using
  the existing Mist controller adapter.

## Software Behavior

The implementation provides:

- typed registry annotations for the Juniper, ERX, and Extreme rows
- native inbound normalization for role, VLAN, ACL, dynamic ACL token, portal,
  VRF, route, address-pool, QoS, accounting identity, tenant, session action,
  CoA, translation, and redacted secret semantics
- outbound reply rendering for selected Juniper, ERX, and Extreme operational
  attributes while preserving generic typed pass-through for rows without a
  neutral runtime semantic
- `Juniper-AV-Pair` parsing and normalization with bounded values and invalid
  token rejection
- Extreme extended VLAN parsing for untagged/tagged VLAN assignments
- ERX rate, service, VRF, pool, IPv6 delegated-pool, PCEF, and bulk CoA
  mappings
- secret redaction for ERX tunnel, PPP, and mobile-IP credential attributes
- durable certification evidence in `juniper_extreme_pack_events`
- admin API, OpenAPI, RBAC, production readiness, system status, support bundle,
  admin UI, Makefile, and CI integration

Rows without a safe neutral behavior remain software-certified as typed
pass-through or typed evidence. That is intentional: AegisNAS exposes the
attribute, source row, codec, semantic family, claim state, and release proof
boundary without silently enforcing behavior that needs real device validation.

## API

```text
GET  /api/v1/system/juniper-extreme-pack
POST /api/v1/system/juniper-extreme-pack/record
GET  /api/v1/system/juniper-extreme-pack/history
```

`GET` returns the generated report, vendor rollups, capability rollups, product
scopes, grammar records, per-attribute records, release scope, and recent
evidence. `record` persists the current source hash, fingerprint, counts,
summary JSON, full report JSON, actor, and timestamp. `history` lists recorded,
blocked, and failed evidence events.

The same status is exposed in:

- `/api/v1/system/status` under `radius.juniper_extreme_pack`
- `/api/v1/system/production-readiness` as `juniper_extreme_pack`
- support bundles as `api/juniper-extreme-pack.json`
- support bundles as `api/juniper-extreme-pack-history.json`
- the Vendor Compatibility admin UI

## Operator Workflow

1. Confirm the active dictionary release profile is the pinned FreeRADIUS 3.2.8
   registry.
2. Inspect `/api/v1/system/juniper-extreme-pack` and confirm software
   completion is 100%.
3. Generate reply previews for the target Juniper, ERX, Extreme, or Mist-backed
   deployment profile.
4. Record software evidence with
   `/api/v1/system/juniper-extreme-pack/record`.
5. Export a support bundle and retain the two Juniper/Extreme pack JSON files.
6. Execute `docs/nas-0063-release-certification-checklist.md` before publishing
   product, firmware, hardware, HA, performance, or customer-certified claims.

## Verification

Run the focused software certification target:

```bash
make test-juniper-extreme-pack
```

The target validates the report, registry contract, packet parser, reply
renderer, database event lifecycle, admin API, OpenAPI, RBAC, readiness,
support bundle capture, and admin UI build.

## Release Boundary

Software implementation is complete when the automated checks pass and the
NAS-0063 report validates all 260 pinned rows with zero software blockers.
External device, controller, production Linux, HA, performance, soak, security,
deployment, and customer acceptance proof is release certification evidence and
does not keep NAS-0063 open for engineering.
