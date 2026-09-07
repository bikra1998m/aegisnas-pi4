# NAS-0069 Nokia And Alcatel-Lucent Service Router Pack

NAS-0069 software-certifies the Nokia and Alcatel-Lucent service-router vendor
pack. The pack covers every Nokia, Alcatel, Alcatel-ESAM,
Alcatel-Lucent-Service-Router, and ALU-AAA row in the pinned FreeRADIUS 3.2.8
VSA registry and maps each row to AegisNAS vendor-neutral semantics or bounded
typed evidence.

The pack covers 334 software-certified rows:

- Nokia: 15 rows for SR OS AVPair policy, user profiles, service-name BCD
  encoding, charging, OCS, APN, tunnel challenge, and redacted credential
  evidence.
- Alcatel: 41 rows for AAT PPP address, DNS, WINS, vrouter, QoS, ATM/FR,
  filter, home-agent, mobile access, accounting, and device evidence.
- Alcatel-ESAM: 33 rows for ESAM access-node, TL1, DHCP, PPPoE, VLAN, VRF,
  QoS, xDSL, transport, and security evidence.
- Alcatel-Lucent-Service-Router: 181 rows for Timetra and Alc SR OS
  subscriber identity, SAP/MSAP services, SLA/QoS, BGP policy, IPv4/IPv6,
  delegated pools, DHCPv6, NAT, deterministic port ranges, portal/WLAN hints,
  charging, accounting counters, and security posture.
- ALU-AAA: 64 rows for access rules, AV-Pairs, service profiles, GSM/AKA/femto
  authentication evidence, NAS identity, location, voice, event, and
  delta-session counters.

## Software Behavior

The implementation provides:

- generated runtime registry mappings for every Nokia, Alcatel, ESAM, SR OS,
  and ALU-AAA row
- distinct vendor pack keys for Nokia, Alcatel AAT, Alcatel ESAM,
  Alcatel-Lucent SR OS, and ALU-AAA
- inbound packet normalization into vendor-neutral role, VLAN, ACL, route, VRF,
  address pool, IPv4/IPv6, delegated-prefix, router-advertisement, DHCPv6,
  translation, portal, device, tenant, accounting, charging, posture, and CoA
  semantics
- Nokia AVPair parsing for route owner, framed routes, VRF, address pools,
  delegated IPv6, NAT64, translation policy, port blocks, ACL/profile hints,
  logging, and accounting keys
- Nokia Service-Name swapped-nibble BCD encode/decode coverage
- ALU SR OS reply rendering for Timetra profile, subscriber profile, SLA
  profile, MSAP policy, BGP policy, delegated IPv6 pool, NAT port range,
  outside IPv4, access-loop downstream rate, portal URL, WLAN VLAN, and shared
  NAS filter rule
- Alcatel AAT and ESAM reply rendering for vrouter/VRF, VLAN, QoS, filter,
  data-filter, and PPP/address evidence
- ALU-AAA reply rendering for service profile, access rule, AV-Pair, NAS
  address, and called-station context
- dynamic ACL compiler support for Nokia and Alcatel profile references plus
  ALU SR OS and ALU-AAA line-rule exports
- redacted evidence handling for GSM, AKA, nonce, key, tunnel challenge, and
  credential-like attributes
- durable certification evidence in `nokia_alu_pack_events`
- admin API, OpenAPI, RBAC, production readiness, system status, support bundle,
  admin UI, Makefile, and CI integration

Rows that require service-router, access-node, AAA, or firmware behavior are
software-certified as typed, bounded evidence with an explicit release
certification boundary. AegisNAS exposes the attribute, source row, codec,
semantic family, claim state, fingerprint, and required external proof without
publishing uncertified hardware claims.

## API

```text
GET  /api/v1/system/nokia-alu-pack
POST /api/v1/system/nokia-alu-pack/record
GET  /api/v1/system/nokia-alu-pack/history
```

`GET` returns the generated report, vendor rollups, capability rollups, product
scopes, grammar records, per-attribute records, release scope, and recent
evidence. `record` persists the current source hash, fingerprint, counts,
summary JSON, full report JSON, actor, and timestamp. `history` lists recorded,
blocked, and failed evidence events.

The same status is exposed in:

- `/api/v1/system/status` under `radius.nokia_alu_pack`
- `/api/v1/system/production-readiness` as `nokia_alu_pack`
- support bundles as `api/nokia-alu-pack.json`
- support bundles as `api/nokia-alu-pack-history.json`
- the Vendor Compatibility admin UI

## Packet Behavior

Nokia packets map as follows:

| Attribute Family | Semantic |
| --- | --- |
| `Nokia-User-Profile` | Role and subscriber profile |
| `Nokia-Service-Name` | Service/device group after swapped-nibble BCD decode |
| `Nokia-AVPair` route forms | VRF, route owner/revision, route policy, framed IPv4/IPv6 routes |
| `Nokia-AVPair` address forms | IPv4 pools, IPv6 pools, delegated-prefix pools, RA prefix pools |
| `Nokia-AVPair` translation forms | Translation policy, owner, revision, mode, public IPv4, NAT64, deterministic port blocks, logging, and accounting keys |
| charging, OCS, APN, and service rows | Accounting, charging, tenant, and subscriber evidence |
| challenge, key, and credential-like rows | Redacted evidence only |

Alcatel AAT and ESAM packets map as follows:

| Attribute Family | Semantic |
| --- | --- |
| `AAT-PPP-Address`, DNS, WINS, default-router fields | IPv4 addressing and access evidence |
| `AAT-Vrouter-Name`, `A-ESAM-VRF-Name` | VRF and route context |
| `AAT-Qos`, `AAT-ATM-Traffic-Profile`, `A-ESAM-QOS-*`, `A-AL-QoS` | QoS and SLA profile evidence |
| `AAT-Filter`, `AAT-Data-Filter`, `A-AL-Security` | ACL, filter, and posture evidence |
| ESAM DHCP, PPPoE, xDSL, TL1, access-node, transport, and security rows | Subscriber, device, accounting, and posture evidence |

Alcatel-Lucent SR OS and ALU-AAA packets map as follows:

| Attribute Family | Semantic |
| --- | --- |
| `Timetra-Profile`, `Alc-Subsc-Prof-Str`, `ALU-AAA-Service-Profile` | Role and service profile |
| `Alc-Subsc-ID-Str`, service, SAP/MSAP, DHCP, PPPoE, ANCP, lease, DSL rows | Subscriber and accounting identity |
| `Alc-SLA-Prof-Str`, access-loop rate, subscriber QoS rows | QoS profile and bandwidth evidence |
| `Alc-BGP-Policy`, route, VRF, pool, IPv6, DHCPv6 rows | Route, address, delegated-prefix, RA, and DHCPv6 context |
| `Alc-Nat-*`, DNAT, NAT64, port-range rows | Translation, public IPv4, NAT64, and deterministic port-block context |
| `Alc-Portal-Url`, redirect, HTTP, WLAN rows | Portal, guest lifecycle, SSID, and VLAN hints |
| `Alc-Nas-Filter-Rule-Shared`, `ALU-AAA-Access-Rule`, `ALU-AAA-AV-Pair` | ACL, dynamic ACL, route, translation, and policy intent |
| ALU-AAA GSM/AKA/femto rows | Redacted mobile-auth evidence |
| ALU-AAA location, called-station, NAS identity, event, and delta-session rows | Tenant, voice, device, accounting, and session evidence |

## Operator Workflow

1. Confirm the active dictionary release profile is the pinned FreeRADIUS 3.2.8
   registry.
2. Inspect `/api/v1/system/nokia-alu-pack` and confirm software completion is
   100%.
3. Enable only the vendor packs that match the receiving device or controller:
   `nokia`, `alcatel`, `alcatel-esam`, `alu-sr`, or `alu-aaa`.
4. Configure Nokia and ALU-AAA AVPair mappings only for strings validated
   against the target firmware.
5. Confirm route, address, VLAN, QoS, translation, ACL, portal, and
   service-chain policies are enabled only for product scopes that have release
   evidence.
6. Record software evidence with `/api/v1/system/nokia-alu-pack/record`.
7. Export a support bundle and retain the two Nokia/ALU pack JSON files.
8. Execute `docs/nas-0069-release-certification-checklist.md` before
   publishing product, firmware, hardware, controller, HA, performance, or
   customer-certified claims.

## Verification

Run the focused software certification target:

```bash
make test-nokia-alu-pack
```

The target validates the report, registry contract, vendor pack catalog,
dictionary release profile, Nokia/ALU packet decoding, BCD handling, reply
rendering, ACL compiler output, route/address/translation policy compatibility,
database event lifecycle, admin API, OpenAPI, RBAC, readiness, support-bundle
capture, and admin UI build.

## Release Boundary

Software implementation is complete when the automated checks pass and the
NAS-0069 report validates all 334 rows with zero software blockers. External
Nokia SR OS, Alcatel AAT, ESAM access-node, Alcatel-Lucent service-router,
ALU-AAA, production Linux FreeRADIUS, HA, performance, soak, security,
deployment, and customer acceptance proof is release certification evidence and
does not keep NAS-0069 open for engineering.
