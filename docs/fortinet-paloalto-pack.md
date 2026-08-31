# NAS-0065 Fortinet and Palo Alto Pack

NAS-0065 software-certifies the Fortinet and PaloAlto dictionary rows from the
pinned FreeRADIUS 3.2.8 VSA registry. It covers the security, firewall, VPN,
posture, administrative role, WLAN, FortiWAN, FortiAuthenticator, FortiNAC,
PAN-OS, GlobalProtect, User-ID, and Panorama metadata that those dictionaries
make visible to a RADIUS server.

The pack covers 42 dictionary rows:

- Fortinet: 32 rows for group and role assignment, client IPv4 and IPv6,
  VDOM and tenant context, interface, SSID, AP, FortiAuthenticator challenge and
  token status, web filter category policy, application control category and
  risk policy, wireless controller accounting context, FortiWAN and host-port
  AVPair policy, FortiDeceptor administrative profile, trusted hosts, SPP
  policy, API access, and FPC user roles.
- PaloAlto: 10 rows for PAN-OS and Panorama administrative role and access
  domains, User-ID group and domain context, client source IP, client OS,
  client hostname, and GlobalProtect client version.

## Software Behavior

The implementation provides:

- typed registry annotations for every pinned Fortinet and PaloAlto row
- native inbound normalization for role, tenant, VRF, device group, posture,
  policy tag, dynamic ACL, route, IPv4, IPv6, accounting identity, certificate
  onboarding, and redacted secret semantics
- outbound reply rendering for Fortinet firewall, WLAN, FortiAuthenticator,
  FortiWAN, FortiDeceptor/FDD, FPC, tenant, Palo Alto PAN-OS, User-ID,
  GlobalProtect, and Panorama attributes
- FortiWAN and host-port AVPair parsing with bounded key-value grammar,
  promotion of known role, ACL, policy, route, tenant, pool, and VRF tokens, and
  invalid token rejection
- Fortinet CoA dynamic-action emission for role, policy, quarantine,
  unquarantine, ACL, and QoS intents through Fortinet group, access profile,
  FDD access profile, FortiWAN AVPair, FPC role, and host-port AVPair fields
- IPv4, IPv6, Ethernet, integer/date text, octet-hex, and bounded string VSA
  decoders
- FortiAuthenticator token and challenge redaction before persistence, logging,
  support bundle capture, or UI display
- durable certification evidence in `fortinet_paloalto_pack_events`
- admin API, OpenAPI, RBAC, production readiness, system status, support bundle,
  admin UI, Makefile, and CI integration

Rows without a safe neutral enforcement behavior are software-certified as typed
pass-through or typed evidence. AegisNAS exposes the attribute, source row,
codec, semantic family, claim state, fingerprint, and release proof boundary
without silently enforcing behavior that requires real Fortinet or Palo Alto
validation.

## API

```text
GET  /api/v1/system/fortinet-paloalto-pack
POST /api/v1/system/fortinet-paloalto-pack/record
GET  /api/v1/system/fortinet-paloalto-pack/history
```

`GET` returns the generated report, vendor rollups, capability rollups, product
scopes, grammar records, per-attribute records, release scope, and recent
evidence. `record` persists the current source hash, fingerprint, counts,
summary JSON, full report JSON, actor, and timestamp. `history` lists recorded,
blocked, and failed evidence events.

The same status is exposed in:

- `/api/v1/system/status` under `radius.fortinet_paloalto_pack`
- `/api/v1/system/production-readiness` as `fortinet_paloalto_pack`
- support bundles as `api/fortinet-paloalto-pack.json`
- support bundles as `api/fortinet-paloalto-pack-history.json`
- the Vendor Compatibility admin UI

## Operator Workflow

1. Confirm the active dictionary release profile is the pinned FreeRADIUS 3.2.8
   registry.
2. Inspect `/api/v1/system/fortinet-paloalto-pack` and confirm software
   completion is 100%.
3. Generate reply previews for the target Fortinet or Palo Alto deployment
   profile.
4. Record software evidence with
   `/api/v1/system/fortinet-paloalto-pack/record`.
5. Export a support bundle and retain the two Fortinet/Palo Alto pack JSON
   files.
6. Execute `docs/nas-0065-release-certification-checklist.md` before publishing
   product, firmware, hardware, HA, performance, or customer-certified claims.

## Verification

Run the focused software certification target:

```bash
make test-fortinet-paloalto-pack
```

The target validates the report, registry contract, packet parser, reply
renderer, Fortinet dynamic-action compiler, database event lifecycle, admin API,
OpenAPI, RBAC, readiness, support bundle capture, and admin UI build.

## Release Boundary

Software implementation is complete when the automated checks pass and the
NAS-0065 report validates all 42 pinned rows with zero software blockers.
External Fortinet appliance, Fortinet controller, PAN-OS, GlobalProtect,
Panorama, production Linux FreeRADIUS, HA, performance, soak, security,
deployment, and customer acceptance proof is release certification evidence and
does not keep NAS-0065 open for engineering.
