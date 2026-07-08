# Enterprise NAS / AAA Vendor Superset Audit

Audit date: 2026-07-07

## Verdict

No. AegisNAS is not a complete enterprise-grade NAS/AAA platform and is not a
superset of the vendors represented by FreeRADIUS dictionaries.

It is a substantial appliance/control-plane prototype built around FreeRADIUS,
SQLite, hostapd, dnsmasq, nftables, Linux traffic control, a Go management
plane, and a React admin UI. It has useful implementations for local and LDAP
identity, selected EAP methods, role/VLAN/rate/ACL replies, accounting,
CoA/Disconnect reception, guest workflows, device inventory, controller
adapters, active/standby orchestration, exports, and rollback. Those features
do not imply parity with the thousands of unrelated functions named by vendor
dictionaries.

The strict result is:

| Measure | Result |
|---|---:|
| Official FreeRADIUS baseline | 3.2.8, commit `032be31bb52646171099617928ec1703335bcf73` |
| Dictionary files scanned | 246 |
| Parsed upstream vendor namespaces | 195 |
| Parsed upstream attributes | 7,654 |
| Third-party attributes with some actual packet mapping | 141 |
| Third-party attributes with no project packet mapping | 7,513 |
| Vendor namespaces with any mapped attribute | 28 / 195 (14.36%) |
| Raw attribute mapping coverage | 1.842% |
| Weighted functional VSA completion | 0.921% |
| Cross-domain feature completion | 29.8% |
| Overall vendor-superset completion | **9.6%** |
| Enterprise production readiness | **38%** |

`Overall vendor-superset completion` weights the dictionary/VSA result at 70%
and the 26 product capability domains at 30%. `Weighted functional VSA
completion` gives 0.5 credit to a partially implemented mapping and zero to an
unmapped attribute. No third-party VSA receives full credit because the
repository has no complete packet-to-policy-to-persistence-to-enforcement-to-
UI-to-certified-device proof for any vendor.

The percentages are engineering audit scores, not marketing measures or a
claim that every attribute has equal business value.

The 38% enterprise-readiness score uses a separate operational rubric: core
enterprise functionality 45% (40% weight), security and secret lifecycle 35%
(20%), reliability/HA/data integrity 40% (20%), and external certification,
scale evidence, release support, and operational proof 25% (20%). This avoids
letting thousands of obscure VSAs hide the maturity of useful core functions,
while still blocking a production-grade claim.

## Evidence Set

The upstream baseline is the signed FreeRADIUS
[`release_3_2_8`](https://github.com/FreeRADIUS/freeradius-server/releases/tag/release_3_2_8)
tag. The exact official
[`share` dictionary tree](https://github.com/FreeRADIUS/freeradius-server/tree/release_3_2_8/share)
was scanned with:

```bash
go run ./cmd/aegis-admin scan-radius-dictionaries \
  --dictionary /path/to/freeradius-server/share \
  --no-built-in --json
```

The repository evidence includes:

- FreeRADIUS generation: `internal/radius/generator.go`, `eap.go`, `apply.go`
- packet broker and VSA handling: `internal/radius/client.go`, `vendor.go`,
  `reply.go`, `mapping.go`
- accounting and sessions: `internal/radius/accounting.go`,
  `internal/sessions/manager.go`, `dynamic_auth.go`
- policy and enforcement: `internal/policy`, `internal/radius/acl*.go`,
  `internal/enforcement`, `internal/firewall`
- Wi-Fi and edge networking: `internal/wireless`, `internal/dnsmasq`,
  `internal/network`
- identity, guest, posture, and certificates: `internal/ldap`,
  `internal/portal`, `internal/onboarding`, `internal/telemetry/profiling.go`
- HA and recovery: `internal/ha`, `internal/upgrade`, network snapshot and
  recovery handlers
- controller integration: Cisco ISE, Aruba Central Classic, Juniper Mist,
  Ruckus SmartZone, FortiGate, MikroTik RouterOS, UniFi Network, Meraki
  Dashboard, and TIP OpenWiFi adapters under `internal/integrations`
- persistence: schema versions 1-13 in `internal/db/migrate.go`
- REST and UI: `cmd/aegis-admin-api`, `internal/adminapi`, and
  `web/admin-ui/src`

The full comparison artifacts are:

- `freeradius-3.2.8-vendor-matrix.md`: the requested 195-row vendor table
- `freeradius-3.2.8-vendor-matrix.csv`: machine-readable vendor scores
- `freeradius-3.2.8-vsa-audit.csv`: all 7,654 attributes, wire metadata,
  inferred capability family, project state, mapped semantic/direction, and
  required implementation work

The dictionary gives wire names, numbers, types, and some enumerations. It does
not define a complete product specification. Where authoritative vendor
documentation and packet captures are absent, the ledger explicitly describes
the functionality as inferred and requires vendor documentation and hardware
certification. Treating an attribute name as proof of behavior would repeat the
mistake this audit is intended to prevent.

## Scanner Finding

The built-in scanner reports 81 exact third-party mappings from compatibility
pack declarations. The runtime packet parser contains additional hard-coded
inbound mappings not registered in those packs. Reconciling by PEN and wire
attribute number finds 141 partially handled attributes across 28 namespaces.

This means the current compatibility API is incomplete in both directions:

- it overstates pack mappings as `implemented` even when only rendering or
  parsing exists;
- it understates inbound mappings that exist in `vendor.go` but are absent from
  the compatibility-pack registry;
- vendor-name normalization misses prefixed names such as several HP, D-Link,
  Airespace, Pica8, and ZTE attributes;
- it does not express whether a mapped value reaches policy, storage,
  enforcement, API/UI, and tested hardware.

The scanner needs a single generated registry consumed by packet code,
compatibility reports, tests, API, and UI.

## Capability Assessment

| # | Domain | Score | Implemented evidence | Partial or missing behavior |
|---:|---|---:|---|---|
| 1 | Authentication | 45% | PAP, CHAP, MS-CHAP, local bcrypt users, LDAP bind, EAP-TLS/PEAP/TTLS/MSCHAPv2 generation | No MFA/OTP/WebAuthn, MAB workflow, AD winbind/Kerberos, EAP-SIM/AKA/AKA', PWD, FAST, TEAP production path, password-change lifecycle, or identity failover policy |
| 2 | Authorization | 35% | Roles and priority rules can assign allow/deny/quarantine, VLAN, bandwidth, timeout, portal, and ACL policy | Small condition language; no expression engine, nested policy sets, per-service authorization, command authorization, subscriber service chains, policy simulation history, or conflict analysis |
| 3 | Accounting | 35% | Start/Stop/Interim, session time, IPv4, octets, basic identity, history and exports | No complete inbound accounting path into the AegisNAS session schema, robust duplicate/reorder handling, gigaword rollover persistence, IPv6/session-route accounting, multi-service correlation, charging records, or 7,513 vendor fields; generated FreeRADIUS SQL points at the product SQLite database, but migrations do not create the standard `radacct`/`radpostauth` tables |
| 4 | CoA/Disconnect | 40% | UDP listener, shared-secret lookup, session lookup, local reclassification and termination, ACK/NAK counters | No general outbound DAC client, RFC error-cause detail, proxy CoA routing, RadSec reverse CoA, vendor command semantics, retry queues, NAS capability discovery, or cluster ownership routing |
| 5 | 802.1X | 40% | FreeRADIUS EAP config and hostapd WPA2/WPA3 Enterprise generation | No production supplicant onboarding profiles, TEAP/EAP chaining, machine/user auth, MAB fallback, fast roaming keys, dynamic authorization across roaming, or broad switch/AP certification |
| 6 | Enterprise Wi-Fi | 25% | Multi-BSS hostapd generation and nine controller adapters with bounded reconciliation | Dynamic VLAN hostapd output lacks a complete VLAN file/bridge lifecycle; no 802.11r/k/v, Passpoint/Hotspot 2.0, DPSK/PPSK, RF/RRM, mesh, location, rogue/WIPS, spectrum, multicast, or full controller estate management |
| 7 | ISP/BRAS/BNG | 5% | A few rate, quota, PPPoE URL, and service-name mappings | No PPPoE termination, subscriber state machine, IP pools, CGNAT, DHCP relay/snooping, L2TP, wholesale realms, service activation, lawful intercept, hierarchical QoS, or BNG route lifecycle |
| 8 | Subscriber management | 15% | Users, sessions, vouchers, quotas in selected attributes, timeouts, bandwidth profiles | No plans/products, recurring quota periods, top-up, balance/charging, concurrent-session policy, family/account hierarchy, prepaid/postpaid, address leases, service bundles, or subscriber portal |
| 9 | Dynamic VLAN | 35% | Standard tunnel attributes plus selected vendor VLAN replies and parsers | No complete local VLAN creation/bridge enforcement from RADIUS, tagged voice/data VLAN policy, QinQ, VLAN pool, fallback VLAN, per-NAS capability negotiation, or broad device certification |
| 10 | Bandwidth/QoS | 30% | Profiles, selected VSAs/WISPr, Linux HTB/IFB per-session IPv4 shaping | No IPv6 shaping, hierarchical classes, DSCP rewrite, queue scheduling, aggregate quotas, time-based rates, burst semantics per vendor, controller reconciliation, or scale testing |
| 11 | ACL/firewall | 30% | Stored ACLs, neutral rule model, selected vendor renderers, nftables quarantine | ACL language is narrow; no lossless vendor AST, object groups, IPv6, application identity, URL categories, dACL lifecycle, stateful per-user policy, compilation diagnostics, or atomic NAS rollback |
| 12 | Route injection | 5% | Operator-defined local static routes | No Framed-Route/Framed-IPv6-Route or vendor route parsing, per-session installation, VRF/routing-instance, BGP/OSPF, route ownership, CoA update, or Stop withdrawal |
| 13 | IPv4/IPv6 | 20% | IPv4 addressing, DHCPv4, NAT, static routes, IPv4 session/firewall/shaping | No DHCPv6/RA/prefix delegation, IPv6 RADIUS assignment, IPv6 ACL/shaping/quarantine, dual-stack subscriber records, NAT64/CGNAT, or IPv6 HA validation |
| 14 | Captive portal | 35% | Portal login, local/LDAP/RADIUS auth, voucher and guest flows, branding fields | DNS redirection is coarse; no HTTPS interception strategy, RFC 8910 captive-portal API, per-session walled garden, social/IdP guest auth, payment, multilingual policy, controller CWA parity, or roaming federation |
| 15 | Hotspot | 30% | WISPr rates, ChilliSpot/Nomadix mappings, vouchers, portal and accounting basics | No complete WISPr XML flow, Passpoint/Hotspot 2.0, venue/operator profiles, roaming consortium, SIM auth, online signup, settlement, quota reset, or carrier offload |
| 16 | Guest access | 55% | Registration, sponsor approval/reject, email/SMS delivery hooks, vouchers, expiry and extensive analytics | External delivery/provider breadth, sponsor delegation policy, legal consent versioning, self-service extensions, IdP/social identity, bulk events, abuse controls, and hardware E2E coverage remain incomplete |
| 17 | Multi-tenant | 30% | Tenant fields, tenant claim, admin tenant scoping and selected VSA mappings | SQLite is shared; no hard row-level isolation, tenant-owned secrets/CAs/dictionaries/controllers, per-tenant quotas, delegated policy trees, billing, data residency, or isolation penetration tests |
| 18 | HA/clustering | 45% | Signed/encrypted replication packages, shared state, VIP lease, fencing/witness policy, active/standby automation and drills | Package replication is not a consensus database; no synchronous session/accounting state, distributed CoA ownership, automatic conflict resolution, multi-node cluster, rolling schema quorum, or certified network partitions |
| 19 | RADIUS proxy | 25% | One generated realm and home-server pool with failover probes | No realm routing table, regex realms, per-tenant pools, loop prevention policy, attribute filtering/rewriting, proxy accounting spool, dynamic discovery, TLS transports, or multi-hop observability |
| 20 | RadSec | 90% | RFC 6614 X.509 mTLS listener and proxy clients, TLS 1.2/1.3, exact peer identity, CA/CRL validation, RADIUS/1.1 ALPN gating, TCP limits, auth/accounting/CoA carriage, active probes, background history, exports, API/UI, readiness checks, and local integration tests | Optional RFC 9813 TLS-PSK is a separate profile; Ubuntu package and physical Cisco/Juniper target certification remain release-lab work |
| 21 | Vendor extensions | 10% | 32 declared packs, 141 actual partial wire mappings, preview API and counters | 7,513 attributes unmapped; no grouped/extended VSA framework, per-release dictionary versioning, semantic conflicts, opaque pass-through policy, or complete vendor packs |
| 22 | NAS management | 45% | Client CRUD and NAS type, config preview/apply/rollback, diagnostics, support bundles, controller drift/push | No dynamic clients, RadSec identities, fleet inventory/config templates, firmware lifecycle, zero-touch provisioning, SNMP/NETCONF/gNMI, TACACS+, config compliance, or full RBAC approval workflow |
| 23 | Security | 35% | TLS 1.2/1.3 bounds, CRL/OCSP options, token auth, OIDC/SAML admin SSO, RBAC, audit, signed/encrypted HA packages, firewall and rollback | Placeholder PEN, secrets in config/SQLite, no HSM/TPM/Vault abstraction, no MFA, no formal key rotation, no FIPS profile, no external security audit/SBOM attestation, and several network services are plain UDP/HTTP by design |
| 24 | Monitoring/reporting | 50% | Prometheus exporter, status checks, histories, compatibility counters, diagnostics/support bundles and many scheduled exports | No distributed tracing, SLO/error-budget model, per-attribute decode metrics, cardinality controls, long-term analytics store, charge records, topology, capacity forecasting, or vendor-certified dashboards |
| 25 | REST/external integrations | 50% | Broad admin REST/OpenAPI surface, SIEM webhook, MDM/compliance HTTP, SSO, nine controller adapters | No stable public API version policy/SDK/webhooks, idempotency keys, async jobs, pagination consistency, secrets manager, integration marketplace, broad ITSM/SOAR/MDM set, or contract certification |
| 26 | Additional dictionary capabilities | 5% | Limited DHCPv4, device profiling and selected voice/mobile fields can be transported only when FreeRADIUS handles them independently | No TACACS+, VMPS, DHCPv6, mobile-core/3GPP charging, WiMAX, cable/DOCSIS, voice call-control accounting, lawful intercept, storage-array admin, or the many specialized functions represented by vendor dictionaries |

## Major Vendor Findings

The full 195-row table is in `freeradius-3.2.8-vendor-matrix.md`. The following
rows explain the highest-priority names and vendor families.

| Vendor/family | Dictionary surface | Current project state | Material missing capability |
|---|---:|---|---|
| Cisco | Cisco 110; ASA 149; VPN3000 116; VPN5000 7; BBSM 1 | Three base Cisco ACL/AVPair mappings; ISE ERS dACL and authorization-profile reconciliation | Full AVPair grammar, command authorization, SGT/TrustSec, VPN/ASA policy, address pools/routes, voice/fax accounting, posture, device administration, and all non-base Cisco namespaces |
| Juniper | Juniper 39; ERX 206 | Seven Juniper mappings; Mist WLAN API | ERX/BNG subscriber services, address pools, routes, QoS, CoS, service activation, IPv6 delegation, lawful intercept, complete Junos firewall semantics |
| Aruba/HPE | Aruba 71; HP 32; Colubris 1; Aerohive 21 | Aruba role/VLAN/ACL/context mappings, HP partial mappings, Aerohive/Extreme mappings, Aruba Central WLAN API | ClearPass role/posture/guest semantics, downloadable roles, full switch/AP attributes, roaming/RF, controller clustering, all remaining attributes and device proof |
| Huawei/H3C | Huawei 197; H3C 62 | Eleven Huawei and seven H3C mappings for role/rate/ACL/portal; no native controller | BRAS/BNG subscriber state, IPv4/IPv6 pools, route/QoS/service chains, command authorization, multicast, accounting/charging, controller/eSight/iMaster integration |
| MikroTik | 32 | Rate-limit/address-list mappings and bounded RouterOS REST reconciliation | Complete rate grammar, queues, address pools/routes, PPP/PPPoE profiles, simultaneous use, hotspot/WISPr, CoA behavior, CAPsMAN, IPv6, and device certification |
| Ubiquiti/UniFi | No namespace in 3.2.8 | Project-defined UBNT PEN 41112 rate parser/renderer and UniFi Network API adapter | Not part of this dictionary baseline; add an authoritative external dictionary source, all UniFi VSAs, controller versions, gateway/VPN/hotspot policy, and certification |
| Meraki | 4 | All four telemetry VSAs parsed; Dashboard SSID reconciliation | VSAs are context only, not full Meraki parity; missing group policy, splash, systems manager posture, switches, appliances, VPN, RF, licensing and broader Dashboard automation |
| Fortinet | 32 | Five mappings and FortiGate FortiAP VAP reconciliation | FortiAuthenticator/FortiNAC semantics, VDOM/admin profiles, VPN, firewall policy, posture, web filtering, FortiSwitch, accounting, CoA and complete CMDB/API coverage |
| Palo Alto | 10 | Five admin/group/client context mappings | Firewall/VPN policy, User-ID/IP-tag lifecycle, GlobalProtect posture, device administration, dynamic address groups, Panorama integration, CoA and all remaining attributes |
| Ruckus | 84 | Nine role/VLAN/portal/device context mappings and SmartZone WLAN API | Dynamic ACL/QoS, DPSK, guest, roaming, WLAN groups, controller cluster/failover, ICX switching, accounting detail and complete API/device proof |
| Cambium | 31 | Seven role/VLAN/rate/walled-garden/accounting mappings | cnMaestro integration, subscriber modules, service flows, QoS details, AP/ePMP differences, portal lifecycle, CoA and all remaining attributes |
| Nokia/Alcatel-Lucent | Nokia 15; SR 181; ALU-AAA 64; Alcatel 41; ESAM 33 | Three Nokia profile/AVPair/service mappings only | SR OS subscriber management, SAP/SDP/service IDs, SLA/QoS, routes, IPv6, accounting/charging, access-node/ESAM and all ALU namespaces |
| Ericsson | Ericsson 110; Ericsson-AB 211; packet-core 2 | No pack or packet mapping | Mobile/broadband subscriber sessions, charging, APN/PDP, policy control, IMS/voice, QoS, roaming, address/route management and device integration |
| Dell/Brocade/Extreme | DellEMC 2; Force10 1; Brocade 7; Foundry 13; Extreme 15 | Extreme role/VLAN/portal mappings; no Dell/Brocade pack | Switch command authorization, roles, VLANs, fabric/VRF, ACL/QoS, telemetry, controller/fabric API, and hardware matrices |
| TP-Link | 9 | Six rate/site/portal mappings | Role/VLAN/ACL, Omada controller-native sync, voucher/portal parity, accounting, CoA and firmware-specific certification |
| D-Link | 9 | Six role/VLAN/rate/ACL mappings | Remaining attributes, switch/AP product variants, controller integration, accounting/CoA and hardware certification |
| Zyxel | 3 | No pack or mapping | Define all three semantics, then add firewall/AP/switch/USG controller and device workflows |
| Netgear | No namespace in 3.2.8 | No pack | Treat as an out-of-corpus target: obtain authoritative dictionary/API specifications and build Insight/AV switching/AP/VPN support separately |
| Starent/Cisco mobile core | 520 | No Starent pack | Subscriber/mobile session control, charging, APN, QoS, lawful intercept, address pools, roaming and full grouped VSA processing |
| 3GPP/3GPP2/WiMAX | 28 / 186 / 292 | No functional implementation | Grouped mobile attributes, charging correlation, SIM/AKA identity, policy control, roaming, QoS/service flows and telecom-grade persistence/scale |

## Requested Name Resolution

Some names in the requested list are brands or product families rather than an
exact 3.2.8 namespace:

- Ubiquiti/UBNT and Netgear are not present in the parsed 3.2.8 `share` tree.
- HPE functionality appears mainly under `HP`, `Aruba`, and `Colubris`.
- Alcatel-Lucent is split across `Alcatel`, `Alcatel-ESAM`,
  `Alcatel-Lucent-Service-Router`, and `ALU-AAA`.
- Dell-related entries are `DellEMC`, `Force10`, and `Equallogic`.
- Cisco functionality is split across `Cisco`, `Cisco-ASA`, `Cisco-BBSM`,
  `Cisco-VPN3000`, `Cisco-VPN5000`, `Airespace`, `Meraki`, and the former
  Starent mobile-core namespace.
- Extreme-related products also appear under `Aerohive`.

Out-of-corpus vendors still require product support, but they cannot be counted
as FreeRADIUS 3.2.8 dictionary parity.

## Missing Feature Implementation Contract

Every missing ledger row must pass all layers below before changing from
`missing` to `partial`, and all layers plus certification before becoming
`implemented`.

| Layer | Required work |
|---|---|
| Authoritative semantics | Link the vendor manual/release and define direction, packet codes, units, cardinality, tags, encryption, enum values, conflicts, defaults, and firmware scope. Dictionary names alone are insufficient. |
| Packet processing | Add typed standard/VSA/extended/grouped encode and decode; preserve repeated/tagged values; reject malformed lengths and unsafe executable text; support Access, Accounting, CoA/Disconnect and proxy directions as applicable. |
| Server policy | Add a vendor-neutral semantic or an explicitly vendor-owned behavior; define precedence, trust boundary, validation, deny behavior, CoA transition and rollback semantics. |
| Persistence | Store normalized values and bounded raw evidence with tenant, NAS, session, direction, source packet, dictionary version and timestamps. Add migrations, indexes, retention and HA replication rules. |
| Configuration | Add per-vendor version/profile, enablement, attribute allowlist, enum/value mappings, units, secrets/certificates, limits and safe defaults. Never enable executable AVPairs or routes by dictionary presence alone. |
| Enforcement | Compile to local nftables/tc/ip/hostapd or a controller/NAS operation; provide preview, idempotency, drift detection, transaction boundaries, post-apply validation, timeout and rollback. |
| REST API | Add OpenAPI schemas, preview/evaluate endpoints, CRUD or import/export, async operation status, pagination, RBAC/tenant checks, audit records and stable errors. |
| UI | Add vendor profile selection, typed editors, capability warnings, unsupported-field visibility, packet/effective-policy preview, drift/health views and rollback controls. |
| Observability | Count parsed/rejected/ignored attributes by vendor/name/direction; expose auth/accounting/CoA/controller outcomes, latency, retries, drift, rollback and compatibility score without unsafe cardinality. |
| Certification | Add golden packet vectors, malformed/fuzz tests, FreeRADIUS integration, pcap assertions, simulator tests, at least one real product/firmware matrix, scale/soak, upgrade/rollback and negative CoA tests. |

Feature-specific additions are mandatory:

- **Authentication/EAP:** identity adapters, method negotiation, credential and
  certificate lifecycle, revocation, channel binding, session resumption,
  machine/user chaining, MFA and failure policy.
- **Accounting/charging:** idempotency keys, sequence/order handling, 64-bit
  counters, gigaword rollover, interim loss recovery, multi-service records,
  quota/charging correlation and durable spool/replay.
- **CoA:** outbound client queues, NAS ownership and capability discovery,
  Error-Cause, retries, proxy routing, cluster handoff and verified enforcement.
- **ACL/QoS:** lossless neutral ASTs, unit-safe compilers/decompilers,
  per-platform limits, deterministic ordering and atomic rollback.
- **Routes/IP:** IPv4/IPv6 pools, delegated prefixes, VRF context, kernel or
  controller ownership, accounting correlation and withdrawal on Stop/CoA.
- **Broadband/mobile:** subscriber/product/service schemas, PPPoE/BNG or mobile
  session state machines, hierarchical QoS, charging and telecom-scale stores.
- **Wi-Fi/hotspot:** complete hostapd VLAN lifecycle, roaming and Passpoint,
  DPSK/PPSK, controller version matrices, RF/security workflows and AP proof.

## Production Blockers

1. The product still defaults to placeholder PEN `55555`. Obtain an IANA PEN,
   freeze the production dictionary identity, and provide migration from lab
   attributes.
2. RadSec is absent. Enterprise proxy and cloud deployments need mTLS/PSK
   transport, lifecycle and interoperability tests.
3. The runtime scanner and packet mappings have two sources of truth and report
   misleading `implemented` states.
4. SQLite and package-based HA do not provide proven synchronous clustered
   session/accounting state or multi-writer consistency.
5. No comprehensive real-vendor hardware/controller matrix proves the current
   mappings. Existing tests are primarily unit/mock/script coverage.
6. ISP/BNG, telecom/mobile, IPv6 subscriber, route injection, TACACS+, and many
   device-administration capabilities are absent.
7. Secret storage, key rotation, MFA, HSM/TPM integration, external security
   review, performance limits, and support lifecycle are not production-grade.
8. Reconcile FreeRADIUS SQL accounting with the product schema. Either install
   and migrate supported `radacct`/`radpostauth` tables with an ingestion path,
   or generate explicit queries that atomically update the AegisNAS session
   model and survive duplicate/interim/out-of-order packets.

## Prioritized Roadmap

### P0: Make Claims Trustworthy

1. Obtain and ship the real IANA PEN; version `dictionary.aegisnas` and add a
   lab-to-production migration tool.
2. Replace hard-coded inbound and renderer switches with one generated typed
   registry. Every entry must declare parse, render, policy, persistence,
   enforcement, UI and certification states independently.
3. Correct vendor alias/prefix matching and expose `mapped`, `packet-tested`,
   `policy-wired`, `enforced`, and `device-certified` instead of one
   `implemented` flag.
4. Add golden packet and malformed/fuzz tests for all 141 current mappings;
   certify the current 28 namespaces before expanding breadth.
5. Add RadSec client/listener/proxy support and production secrets/certificate
   rotation.

### P1: Complete Enterprise AAA Core

1. Add MAB, AD/winbind/Kerberos, MFA, TEAP/method chaining, machine/user auth,
   and complete EAP-TLS enrollment/revocation.
2. Build durable inbound accounting with idempotency, spool/replay, gigawords,
   IPv6 and complete session correlation.
3. Build outbound CoA/Disconnect, proxy CoA, Error-Cause/retries and HA-aware
   NAS ownership.
4. Replace the small policy matcher with a typed expression engine, simulation,
   versioning, approval, conflict analysis and tenant isolation.
5. Move production state to PostgreSQL or another supported replicated store;
   retain SQLite only for Lite mode.

### P2: Finish Network Enforcement

1. Complete dual-stack DHCP/RA/prefix delegation, IPv6 firewall/shaping and
   RADIUS address/pool/route semantics.
2. Implement neutral ACL and hierarchical QoS compilers with per-vendor limits,
   previews, atomic apply and rollback.
3. Complete dynamic VLAN bridge/subinterface lifecycle, tagged VLANs, voice
   VLANs, QinQ and fallback behavior.
4. Replace coarse portal DNS interception with per-session state, RFC 8910,
   safe walled gardens and controller CWA integration.

### P3: Vendor Waves

1. Enterprise access wave: Cisco/Airespace/ASA, Aruba/HP, Juniper/Extreme,
   Ruckus, Fortinet, Palo Alto, Meraki, UniFi, Cambium, TP-Link and D-Link.
2. Broadband wave: Juniper ERX, Huawei, H3C, Nokia/ALU SR, ZTE, MikroTik,
   Ericsson, Calix, Adtran, Alphion and access-node vendors.
3. Mobile/charging wave: Starent, 3GPP, 3GPP2, Ericsson packet core, WiMAX and
   Alvarion. This requires a separate telecom architecture, not more switch
   cases in the current session model.
4. Voice/VPN/device-admin wave: BroadSoft, AudioCodes, Digium, Cisco VPN/ASA,
   Altiga, Nortel, Lucent, Acme and TACACS+/command authorization.
5. Long-tail wave: generate typed stubs for every remaining namespace, rank by
   customer demand and hardware availability, and never claim parity before
   certification.

### P4: Certification and Operations

1. Maintain vendor/firmware/controller matrices and legal access to vendor
   specifications.
2. Run packet capture, negative/fuzz, failover, upgrade, rollback, load and
   30-day soak tests for every certified feature.
3. Publish compatibility by exact vendor, product, firmware, transport,
   attribute and direction.
4. Add SLOs, distributed tracing, long-term metrics, capacity models, SBOM and
   signed release attestations.

## Definition of 100%

One hundred percent cannot mean “all dictionary names parse.” It means every
attribute is either:

- fully implemented with authoritative semantics and end-to-end certification;
- intentionally pass-through with bounded, tested, policy-controlled behavior;
  or
- explicitly not applicable to the product, with a documented rationale that
  is excluded from the denominator only after product governance approval.

Even after all 7,654 attributes are classified, being a literal superset of
every vendor also requires non-RADIUS capabilities that dictionaries cannot
describe: radio management, switching/routing protocols, firewall engines,
BNG/mobile charging, controller clusters, firmware, optics, hardware
acceleration and vendor cloud services. The realistic product target is a
vendor-neutral AAA/NAC/NAS control plane with certified adapters, not a single
box that reproduces every vendor's entire product portfolio.
