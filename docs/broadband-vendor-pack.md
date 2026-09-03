# NAS-0068 Huawei, H3C, and ZTE Broadband Pack

NAS-0068 software-certifies the broadband vendor pack for Huawei, H3C, and ZTE
dictionary coverage. The pack covers every Huawei, H3C, and ZTE row in the
pinned FreeRADIUS 3.2.8 VSA registry and maps each row to AegisNAS
vendor-neutral broadband semantics or bounded typed evidence.

The pack covers 308 software-certified rows:

- Huawei: 197 rows for BRAS/BNG subscriber state, QoS, address pools, routes,
  NAT/translation, portal, command authorization, accounting, charging,
  multicast, WLAN/AP context, tenant/domain context, and redacted credential
  evidence.
- H3C: 62 rows for Comware/iMC role, group, portal, ITA policy, QoS,
  NAT/translation, subscriber identity, DNS, VRF, multicast, accounting, and
  device context.
- ZTE: 49 rows for ZX/BNG PPPoE portal hints, QoS profile and SCR rates,
  IPv6 rate variants, privilege role mapping, multicast limits, tunnel
  controls, DNS, domain/VPN context, and subscriber/accounting evidence.

## Software Behavior

The implementation provides:

- generated runtime registry mappings for every Huawei, H3C, and ZTE row
- inbound packet normalization into vendor-neutral role, policy, route, pool,
  translation, DNS, portal, accounting, and rate semantics
- Huawei reply rendering for role, QoS, average and peak rates, data filter,
  redirect URL, AVPair grammar, direct NAT policy/address/port-block fields,
  route, address, and translation policy evidence
- H3C reply rendering for role, group, average and peak rates, ITA policy,
  portal URL, AVPair grammar, direct NAT address and port-block fields, route,
  address, and translation policy evidence
- ZTE reply rendering for QoS profiles, IPv4 and IPv6 SCR rate controls,
  PPPoE URL, and numeric privilege roles
- broadband AVPair parsing for VRF, route policy, framed routes, address pools,
  delegated IPv6 prefix pools, translation policy, public IPv4, NAT64 prefix,
  port blocks, ACL/profile hints, and logging/accounting correlation
- redacted typed evidence for Huawei password, DPSK, and web-authentication
  fields
- durable certification evidence in `broadband_vendor_pack_events`
- admin API, OpenAPI, RBAC, production readiness, system status, support bundle,
  admin UI, Makefile, and CI integration

Rows that require controller, BRAS/BNG, or firmware behavior are
software-certified as typed, bounded evidence with an explicit release
certification boundary. AegisNAS exposes the attribute, source row, codec,
semantic family, claim state, fingerprint, and required external proof without
publishing uncertified hardware claims.

## API

```text
GET  /api/v1/system/broadband-vendor-pack
POST /api/v1/system/broadband-vendor-pack/record
GET  /api/v1/system/broadband-vendor-pack/history
```

`GET` returns the generated report, vendor rollups, capability rollups, product
scopes, grammar records, per-attribute records, release scope, and recent
evidence. `record` persists the current source hash, fingerprint, counts,
summary JSON, full report JSON, actor, and timestamp. `history` lists recorded,
blocked, and failed evidence events.

The same status is exposed in:

- `/api/v1/system/status` under `radius.broadband_vendor_pack`
- `/api/v1/system/production-readiness` as `broadband_vendor_pack`
- support bundles as `api/broadband-vendor-pack.json`
- support bundles as `api/broadband-vendor-pack-history.json`
- the Vendor Compatibility admin UI

## Packet Behavior

Huawei packets map as follows:

| Attribute Family | Semantic |
| --- | --- |
| `Huawei-User-Class`, command and access-service fields | Role and command authorization evidence |
| `Huawei-Qos-Profile-Name`, `Huawei-Down-QOS-Profile-Name`, rate and burst fields | Bandwidth/QoS profile, upload, and download bandwidth |
| `Huawei-Data-Filter`, `Huawei-AVpair` ACL hints | ACL and dynamic policy evidence |
| `Huawei-HTTP-Redirect-URL`, portal fields | Portal profile and guest lifecycle evidence |
| `Huawei-Framed-Pool`, IPv4/IPv6/DHCPv6/prefix fields | Address, pool, DHCPv6, RA, and delegated-prefix intent |
| `Huawei-AVpair` route forms | VRF, route policy, and framed route intent |
| `Huawei-NAT-*`, translation AVPair forms | NAT/translation policy, public IPv4, NAT64, port block, logging, and accounting intent |
| password, DPSK, and web-authentication fields | Redacted evidence only |

H3C packets map as follows:

| Attribute Family | Semantic |
| --- | --- |
| `H3C-User-Role`, `H3C-User-Group`, command fields | Role, group, and command authorization evidence |
| `H3C-Input-Average-Rate`, `H3C-Output-Average-Rate`, peak rates | Upload/download bandwidth |
| `H3C-Ita-Policy`, `H3C-Av-Pair` | Policy tag, route, address, translation, ACL, NAT64, and service evidence |
| `H3C-NAT-IP-Address`, `H3C-NAT-Start-Port`, `H3C-NAT-End-Port` | Public IPv4 and deterministic port-block intent |
| DNS, VRF, subscriber, multicast, accounting, and backup NAS fields | Typed broadband operational evidence |

ZTE packets map as follows:

| Attribute Family | Semantic |
| --- | --- |
| `ZTE-PPPOE-URL` | Portal or PPPoE access hint |
| `ZTE-SW-Privilege` | Role through numeric role mappings |
| `ZTE-QoS-Profile-*`, `ZTE-Rate-Ctrl-SCR-*` | QoS profile and upload/download bandwidth, including IPv6 variants |
| multicast and tunnel fields | Policy tag and subscriber-service evidence |
| DNS, domain, VPN, and subscriber fields | Addressing, tenant, posture, and accounting evidence |

## Operator Workflow

1. Confirm the active dictionary release profile is the pinned FreeRADIUS 3.2.8
   registry.
2. Inspect `/api/v1/system/broadband-vendor-pack` and confirm software
   completion is 100%.
3. Configure numeric role mappings for ZTE privilege levels and any target
   Huawei/H3C integer-role conventions.
4. Configure Huawei/H3C AVPair mappings only for firmware-validated strings.
5. Confirm translation, route, address, VLAN, QoS, and service-chain policies
   are enabled only for product scopes that have release evidence.
6. Record software evidence with `/api/v1/system/broadband-vendor-pack/record`.
7. Export a support bundle and retain the two broadband-vendor pack JSON files.
8. Execute `docs/nas-0068-release-certification-checklist.md` before publishing
   product, firmware, hardware, controller, HA, performance, or
   customer-certified claims.

## Verification

Run the focused software certification target:

```bash
make test-broadband-vendor-pack
```

The target validates the report, registry contract, vendor pack catalog,
dictionary release profile, Huawei/H3C/ZTE packet decoding, rate rendering,
translation policy output, database event lifecycle, admin API, OpenAPI, RBAC,
readiness, support bundle capture, and admin UI build.

## Release Boundary

Software implementation is complete when the automated checks pass and the
NAS-0068 report validates all 308 rows with zero software blockers. External
Huawei MA/NE/CloudEngine/WLAN/iMaster, H3C Comware/iMC/BRAS/BNG, ZTE
ZX/BNG/PPPoE, production Linux FreeRADIUS, HA, performance, soak, security,
deployment, and customer acceptance proof is release certification evidence and
does not keep NAS-0068 open for engineering.
