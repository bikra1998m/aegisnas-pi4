# Feature Capability Framework

This document defines how AegisNAS enables, warns on, degrades, or blocks features based on hardware, deployment form, and integration readiness.

Use it together with:

- [Deployment Profiles](deployment-profiles.md)
- [Hardware Sizing And Deployment Matrix](hardware-sizing-and-deployment-matrix.md)
- [Wireless Access And UI Guide](wireless-access-ui-guide.md)
- [External AAA Product Mode](external-aaa-product-mode.md)

## Goal

AegisNAS should remain one product and one codebase across:

- lab VMs
- low-power appliances
- standard branch appliances
- higher-capacity enterprise appliances

The product should not assume every target can safely run every feature. Instead, each feature should have a capability state derived from:

- deployment profile
- deployment form
- hardware hints
- local hardware presence
- integration readiness

That gives the operator:

- predictable defaults
- fewer invalid combinations
- clearer warnings
- a cleaner path from lab to production

## Capability States

Every major feature should resolve to one of these states at runtime:

| State | Meaning |
| --- | --- |
| `enabled` | Feature is allowed and active. |
| `available` | Feature is supported on this target, but not active yet. |
| `warned` | Feature is allowed, but the current target is below the recommended floor or missing a supporting dependency. |
| `degraded` | Feature is active, but the product is intentionally reducing scope or polling frequency to protect the platform. |
| `blocked` | Feature is not allowed on this target or in the current configuration. |

Examples:

- local wireless on a VM with no radio passthrough: `blocked`
- runtime shaping on a 2 vCPU lab VM: `warned` or `degraded`
- full AI mode on an enterprise appliance with a configured provider: `available` or `enabled`
- posture engine with no MDM or profiling inputs: `blocked`

## Capability Inputs

The feature evaluator should use the following inputs.

### Deployment Inputs

- `deployment.profile`
  - `lite`
  - `branch`
  - `enterprise`
  - `custom`
- `deployment.form`
  - `physical`
  - `virtual`
- `deployment.hardware.memory_mb`
- `deployment.hardware.cpu_cores`
- `deployment.hardware.storage_gb`
- `deployment.hardware.prefer_external_ap`
- `deployment.hardware.wireless_passthrough`

### Hardware Inputs

- wired NIC count
- real Wi-Fi radio detected or not
- USB or PCI passthrough radio present or not
- downstream shaping interface present or not
- persistent storage headroom

### Integration Inputs

- upstream AAA configured or not
- LDAP configured or not
- email or SMS provider configured or not
- certificate authority configured or not
- MDM or UEM connector configured or not
- telemetry sink configured or not
- AI provider endpoint and model configured or not

## Current Foundation In Repo

The current codebase now has a working form of this model through:

- deployment profiles
- deployment form
- hardware hints
- dashboard mismatch warnings
- automatic Lite, Branch, and Enterprise scaling derived from CPU, RAM, and storage hints
- profile-driven defaults for AI, telemetry, shaping, and RADIUS scale
- Access Settings capability preview for phases 1 through 5
- runtime status surfacing for SSO, SIEM export, and controller automation
- NAS-0060 vendor mapping certification for the 141 current partial
  FreeRADIUS mappings, with software completion separated from external
  hardware and production release certification
- NAS-0061 Cisco-family pack certification for all 922 pinned Cisco,
  Airespace/WLC, ASA/VPN, Starent, and Meraki rows, with Cisco-AVPair grammar,
  typed pass-through, API/UI evidence, and external release certification split
- NAS-0062 Aruba/HPE-family pack certification for all 125 pinned Aruba,
  HP/ArubaOS-Switch, Aerohive/Extreme, and Colubris/MSM rows, with policy
  grammar, secret redaction, typed pass-through, API/UI evidence, and external
  release certification split
- NAS-0063 Juniper/ERX/Extreme/Mist pack certification for all 260 pinned
  Juniper, ERX, and Extreme rows plus Mist product scope, with Juniper AVPair
  grammar, ERX subscriber and BNG normalization, Extreme netlogin handling,
  secret redaction, typed pass-through, API/UI evidence, and external release
  certification split
- NAS-0064 Ruckus/ICX pack certification for all 97 pinned Ruckus and Foundry
  rows, with Ruckus FlexAuth grammar, DPSK/subscriber redaction, WLAN and guest
  context, QoS/quota, mobile-core accounting, ICX command authorization,
  access-list handling, typed pass-through, API/UI evidence, and external
  release certification split
- NAS-0065 Fortinet/Palo Alto security pack certification for all 42 pinned
  Fortinet and PaloAlto rows, with Fortinet VDOM, FAC token/challenge
  redaction, web filter, application control, FortiWAN and host-port AVPairs,
  FortiDeceptor/FDD, FPC role, Palo Alto PAN-OS, User-ID, GlobalProtect,
  Panorama handling, typed pass-through, API/UI evidence, and external release
  certification split
- NAS-0066 Meraki/UniFi/OpenWiFi cloud-controller pack certification for all 4
  pinned Meraki rows, 1 pinned OpenWiFi row, and 2 AegisNAS-runtime UBNT rate
  rows, with Meraki telemetry, OpenWiFi AP identity, UniFi bps rate
  parser/renderer behavior, cloud controller adapter scope, API/UI evidence,
  and external release certification split
- NAS-0067 Cambium/TP-Link/D-Link access pack certification for all 49 pinned
  Cambium, TPLink, and Dlink rows, with Cambium cnMaestro/ePMP/PMP role, VLAN,
  quota, QoS, walled-garden, and TLV evidence, TP-Link Omada rate/site/group,
  portal, command, and authentication-key redaction evidence, D-Link user-level,
  bandwidth, priority, VLAN, ACL profile/rule/script handling, API/UI evidence,
  and external release certification split
- NAS-0068 Huawei/H3C/ZTE broadband pack certification for all 308 pinned
  Huawei, H3C, and ZTE rows, with BRAS/BNG subscriber state, route, address
  pool, QoS, NAT/translation, multicast, command authorization, portal,
  accounting, charging, redacted credential evidence, API/UI evidence, and
  external release certification split
- NAS-0069 Nokia/Alcatel-Lucent service-router pack certification for all 334
  pinned Nokia, Alcatel, Alcatel-ESAM, Alcatel-Lucent-Service-Router, and
  ALU-AAA rows, with Nokia AVPair/profile/BCD service-name handling, Alcatel
  AAT address/QoS/filter evidence, ESAM VRF/VLAN/QoS/DHCP/PPPoE evidence, ALU
  SR OS subscriber/SLA/route/IPv6/NAT/portal/accounting/charging/CoA semantics,
  ALU-AAA access-rule/AVPair/location/event/mobile-auth redaction evidence,
  API/UI evidence, and external release certification split
- NAS-0070 MikroTik RouterOS pack certification for all 32 pinned MikroTik rows,
  with PPP/PPPoE quota and gigawords handling, RouterOS rate-limit grammar,
  group/profile role assignment, firewall address-list and switching-filter
  ACL profile references, tenant realm and mark-id selectors, hotspot advertise
  URL/interval handling, IPv4 host and IPv6 delegated-pool hints, CAPsMAN
  wireless posture/VLAN/signal/comment handling, DHCP option evidence, wireless
  key redaction, API/UI evidence, and external release certification split
- NAS-0071 enterprise switching vendor pack certification for all 69 pinned
  3Com, Dell EMC, EqualLogic, Brocade, Force10, Foundry, Arista, and Extreme
  rows, with role/privilege mapping, command authorization context, VLAN and
  fabric selectors, ACL/profile assignment, AVPair grammar, QoS, captive portal
  and WebAuth hints, session remediation, VRF, device/posture context,
  administrative identity, accounting evidence, API/UI evidence, and external
  release certification split
- NAS-0072 long-tail typed namespace program certification for all 1,126 pinned
  rows across 92 remaining in-corpus FreeRADIUS vendor namespaces, with neutral
  role, VLAN, ACL/filter, bandwidth, quota, portal, address, route, VRF,
  posture, tenant, controller, certificate, accounting, CoA, typed
  pass-through, redacted secret evidence, API/UI evidence, and external release
  certification split
- NAS-0073 out-of-corpus vendor intake for authoritative external dictionaries
  such as UBNT, Netgear, and future vendor sources, with provenance, SHA-256,
  license, PEN, parser, semantic classification, packet safety, redaction,
  API/UI evidence, durable intake history, production readiness, support bundle
  capture, and external release certification split

That work lives primarily in:

- `internal/config/profile.go`
- `internal/config/config.go`
- `configs/vendor_mapping_certification.go`
- `configs/cisco_family_pack.go`
- `configs/aruba_family_pack.go`
- `configs/juniper_extreme_pack.go`
- `configs/ruckus_icx_pack.go`
- `configs/fortinet_paloalto_pack.go`
- `configs/cloud_controller_pack.go`
- `configs/access_vendor_pack.go`
- `configs/broadband_vendor_pack.go`
- `configs/nokia_alu_pack.go`
- `configs/mikrotik_pack.go`
- `configs/switching_vendor_pack.go`
- `configs/long_tail_namespace.go`
- `configs/external_vendor_intake.go`
- `internal/radius/cisco_avpair.go`
- `internal/radius/aruba_family.go`
- `internal/radius/juniper_extreme.go`
- `internal/radius/fortinet_paloalto.go`
- `internal/radius/nokia_alu.go`
- `internal/radius/mikrotik.go`
- `internal/radius/switching_vendor.go`
- `internal/radius/long_tail_namespace.go`
- `internal/db/nokia_alu_pack.go`
- `internal/db/mikrotik_pack.go`
- `internal/db/switching_vendor_pack.go`
- `internal/db/long_tail_namespace.go`
- `internal/db/external_vendor_intake.go`
- `internal/adminapi/nokia_alu_pack.go`
- `internal/adminapi/mikrotik_pack.go`
- `internal/adminapi/switching_vendor_pack.go`
- `internal/adminapi/long_tail_namespace.go`
- `internal/adminapi/external_vendor_intake.go`
- `internal/radius/vendor.go`
- `web/admin-ui/src/pages/AccessSettings.tsx`
- `web/admin-ui/src/pages/VendorCompatibility.tsx`
- `web/admin-ui/src/pages/Dashboard.tsx`

This framework explains the product behavior that now exists in the repo and the boundaries that still matter for deployment.

## Automatic Scaling Plan

The runtime derives `deployment.scaling` from declared CPU, memory, and storage:

| Scaling mode | Selection rule | Retention target | Feature posture |
| --- | --- | --- | --- |
| `lite` | below branch floor, or missing CPU/RAM | 24h analytics, 6h profiling, 900s lease-history polling | gate shaping, onboarding, posture, controller automation, SSO, HA, and tenant governance when active |
| `branch` | 2 cores, 4096 MB RAM, and unknown or at least 32 GB storage | 168h analytics, 24h profiling, 300s lease-history polling | allow branch workflows, gate enterprise certificate, posture, HA, and multi-tenant controls |
| `enterprise` | 4 cores, 8192 MB RAM, and unknown or at least 64 GB storage | 720h analytics, 168h profiling, 60s lease-history polling | allow the full feature set subject to per-integration validation |

The scaling plan includes:

- `mode`
- `selected_profile`
- `recommended_profile`
- `can_run_selected`
- `recommended_retention`
- `recommended_limits`
- `gating_actions`

Capability evaluation applies active `gating_actions` after normal dependency checks. That means an otherwise valid feature can still be returned as `blocked` or `warned` when the declared hardware is too small for the selected profile.

Unknown storage does not force a downgrade during upgrade from older configs, but `storage_known` stays false so operators can finish sizing before relying on long retention.

## Feature Groups

### 1. Core Access Plane

These are the core product features and should be usable on all supported targets.

| Feature | Lite | Branch | Enterprise | Notes |
| --- | --- | --- | --- | --- |
| Captive portal | enabled | enabled | enabled | core product path |
| Local users | enabled | enabled | enabled | low resource cost |
| Vouchers | enabled | enabled | enabled | low resource cost |
| Session tracking | enabled | enabled | enabled | core product path |
| Session termination | enabled | enabled | enabled | core operator workflow |
| Local policy engine | enabled | enabled | enabled | core product path |
| FreeRADIUS broker | enabled | enabled | enabled | core product path |
| Accounting start/interim/stop | enabled | enabled | enabled | core AAA function |
| CoA / Disconnect | available | enabled | enabled | may be warned on smaller targets with high churn |

### 2. Wireless And Appliance Features

These features depend heavily on physical platform shape.

| Feature | Lite | Branch | Enterprise | Notes |
| --- | --- | --- | --- | --- |
| External AP model | enabled | enabled | enabled | safest VM and branch path |
| Local `hostapd` radio mode | warned | enabled | enabled | requires supported physical radio |
| Wireless enabled on plain VM NIC | blocked | blocked | blocked | not a real radio |
| Multi-SSID local appliance mode | warned | enabled | enabled | capacity depends on radio and CPU |
| Dynamic VLAN SSIDs | available | enabled | enabled | strongest on enterprise gear; hostapd config uses fallback `dynamic_vlan=1` or fail-closed `dynamic_vlan=2` and points to the managed VLAN file |
| 802.11r/k/v roaming lifecycle | available | enabled | enabled | renders FT, RRM, BSS transition, PMF, neighbor AP, and key-reference-safe hostapd intent; real roam and packet-capture proof remain release certification |
| Passpoint and Hotspot 2.0 lifecycle | available | enabled | enabled | renders 802.11u/HS2.0 ANQP, venue/operator, domain, roaming consortium, NAI realm, 3GPP, WAN metrics, connection capability, and OSU hostapd intent; real AP/client/carrier proof remains release certification |
| Tagged VLAN/QinQ policy | available | enabled | enabled | compiler is lightweight; production claims need packet capture and vendor-device certification |
| Per-session route/VRF policy | available | enabled | enabled | compiler is lightweight; active ownership and Stop withdrawal are software-ready; native vendor route behavior needs certification |
| Dynamic subscriber route export | available | enabled | enabled | publishes owned routes into FRR BGP/OSPF plans with snapshots, withdrawal, and rollback; live routing proof needs release certification |
| IPv4/IPv6 pools, DHCPv6, RA, and prefix delegation | available | enabled | enabled | compiler and ownership ledger are software-ready; native DHCPv6/RA/device enforcement needs release certification |
| CGNAT, NAT64, and deterministic subscriber translation | warned | available | enabled | compiler and ownership ledger are software-ready; native dataplane, lawful logging, and vendor enforcement need release certification |
| Atomic enforcement transactions and drift rollback | available | enabled | enabled | transaction ledger, compensation, drift checks, APIs, and UI are software-ready; physical dataplane, controller, HA, and soak evidence need release certification |

Rules:

- if `deployment.form` is `virtual` and no passthrough radio exists, local wireless is `blocked`
- if `prefer_external_ap` is true, the UI should recommend external AP mode even on physical targets

### 3. Guest Access Workflows

These are the first major expansion area for a stronger NAC product.

| Feature | Lite | Branch | Enterprise | Notes |
| --- | --- | --- | --- | --- |
| Basic guest login | enabled | enabled | enabled | already present |
| Voucher guest flow | enabled | enabled | enabled | already present |
| Portal branding | enabled | enabled | enabled | already present |
| Terms and logout URL control | enabled | enabled | enabled | already present |
| Guest self-registration | blocked | available | enabled | runtime-supported through the captive portal and `Guest Requests` |
| Sponsor approval | blocked | available | enabled | runtime-supported by email or SMS approval links |
| Email or SMS invite | blocked | warned | enabled | runtime exists; depends on provider setup |
| Guest lifecycle reporting | available | enabled | enabled | stronger value on branch and enterprise |

Rules:

- sponsor approval should be `blocked` unless email or approval transport is configured
- self-registration should not be shown as ready if portal pages and approval destinations are incomplete

### 4. BYOD And Onboarding

These features separate a serious NAC suite from a basic portal appliance.

| Feature | Lite | Branch | Enterprise | Notes |
| --- | --- | --- | --- | --- |
| Device registration inventory | blocked | available | enabled | runtime-supported through the `Devices` page |
| Onboarding portal | blocked | warned | enabled | runtime-supported; still policy and CA dependent |
| Certificate enrollment | blocked | blocked | enabled | runtime-supported with internal or external CA mode |
| EAP-TLS onboarding | blocked | blocked | enabled | requires strong certificate handling and TLS EAP defaults |
| Known device reissue and revocation | blocked | blocked | enabled | enterprise-only first pass |

Rules:

- onboarding should be `blocked` unless certificate and identity dependencies exist
- EAP-TLS onboarding should stay blocked outside the enterprise tier and should also block on underpowered enterprise hardware

### 5. Profiling And Posture

This is the biggest gap against larger NAC platforms today.

| Feature | Lite | Branch | Enterprise | Notes |
| --- | --- | --- | --- | --- |
| Simple device grouping | available | enabled | enabled | can be role or tag based |
| MAC-based device inventory | available | enabled | enabled | useful base layer |
| Passive device profiling | blocked | warned | enabled | runtime-supported with collector and retention limits |
| Endpoint posture checks | blocked | blocked | enabled | runtime-supported when MDM or compliance inputs exist |
| MDM or UEM compliance ingest | blocked | blocked | enabled | runtime-supported; integration-heavy |
| Remediation and quarantine workflows | available | enabled | enabled | stronger when posture exists |

Rules:

- posture should be `blocked` unless integration sources are configured
- profiling should degrade polling depth and retention on constrained hardware

### 6. Policy And Enforcement Depth

This is where dictionary support becomes product behavior.

| Feature | Lite | Branch | Enterprise | Notes |
| --- | --- | --- | --- | --- |
| Role mapping | enabled | enabled | enabled | already present |
| VLAN assignment | enabled | enabled | enabled | already present |
| Timeout policy | enabled | enabled | enabled | already present |
| Bandwidth profile mapping | available | enabled | enabled | already present |
| Vendor dictionary catalog | enabled | enabled | enabled | read-only parser and semantic registry are low resource |
| Vendor compatibility packs | enabled | enabled | enabled | metadata and conservative reply rendering are low resource |
| Runtime shaping | warned | enabled | enabled | depends on downstream interface and hardware |
| Hierarchical QoS scheduler | available | enabled | enabled | compiles bandwidth profiles into aggregate and per-session `tc`/IFB classes with snapshots and rollback |
| Dual-stack shaping and rate compiler | available | enabled | enabled | adds IPv6-only/dual-stack `tc flower` classifiers and vendor-safe kbps, bps, and MikroTik grammar rendering |
| Dynamic VLAN lifecycle | available | enabled | enabled | creates owned Linux bridges, VLAN subinterfaces, hostapd VLAN file entries, hostapd dynamic SSID bindings, cleanup previews, snapshots, history, and rollback from VLAN intent |
| Dynamic subscriber route export | available | enabled | enabled | compiles `route_policy_ownership` into BGP/OSPF/OSPF3 FRR artifacts, dampening, withdrawal plans, snapshots, and atomic transaction participation |
| Quarantine enforcement | enabled | enabled | enabled | already present |
| Stateful local firewall policy | available | enabled | enabled | owned nftables table enforces per-session ACL and quarantine policy with IPv4/IPv6 snapshots |
| ACL-like policy language | available | enabled | enabled | persisted policies feed live decisions, RADIUS replies, local firewall enforcement, and controller reconciliation |
| Vendor-aware enforcement adapters | available | enabled | enabled | conservative RADIUS mappings and native controller clients are selected per NAS profile |

Rules:

- shaping should be `blocked` if no shaping interface exists
- vendor dictionary parsing should stay read-only and cheap on lite hardware
- local ACL, VLAN lifecycle, and subscriber route export enforcement should require preview/apply evidence before production use; device-side and routing-daemon enforcement still need release certification evidence

### 7. Identity And Enterprise Integrations

| Feature | Lite | Branch | Enterprise | Notes |
| --- | --- | --- | --- | --- |
| LDAP auth | available | enabled | enabled | already present |
| Upstream RADIUS / AAA | available | enabled | enabled | already present |
| Local fallback | enabled | enabled | enabled | already present |
| SAML or OIDC admin auth | blocked | available | enabled | runtime-supported with break-glass fallback |
| MDM or UEM integration | blocked | blocked | enabled | runtime-supported with token-backed sync |
| SIEM / webhook export | available | enabled | enabled | can scale by retention depth |
| Multi-tenant separation | blocked | blocked | available | runtime-supported for tenant-scoped admin operations |

### 8. Operations And Governance

| Feature | Lite | Branch | Enterprise | Notes |
| --- | --- | --- | --- | --- |
| Dashboard and service health | enabled | enabled | enabled | already present |
| Alerts | available | enabled | enabled | already present |
| Revisions / staged apply / rollback | enabled | enabled | enabled | already present |
| Backup and restore | enabled | enabled | enabled | already present |
| AI recommendations | blocked | enabled | enabled | existing profile system already trends this way |
| Full AI mode | blocked | warned | enabled | requires configured provider |
| Delegated admin / RBAC | blocked | available | enabled | runtime-supported with local and external-group mapping |
| Rich reporting and analytics | warned | available | enabled | dashboard, alerts, exports, and audit visibility are present; long-horizon analytics remain lighter than large NAC suites |

## Profile Behavior Summary

### `lite`

Use `lite` for:

- small VMs
- Raspberry Pi class appliances
- demos and lab bring-up
- constrained branch pilots

Default direction:

- keep core AAA, portal, sessions, and policy enabled
- keep guest workflows simple
- keep local wireless conditional on real hardware
- disable or warn on heavy analytics, posture, and onboarding
- prefer external APs

### `branch`

Use `branch` for:

- the default branch appliance
- real guest and employee edge deployments
- mixed portal and WPA Enterprise use

Default direction:

- enable shaping when the platform can support it
- allow stronger guest workflows
- allow upstream AAA and normal live operations
- keep enterprise-only onboarding and posture optional

### `enterprise`

Use `enterprise` for:

- higher-capacity edge appliances
- stronger EAP and policy demand
- richer visibility and recommendation workflows
- advanced NAC feature sets

Default direction:

- full AI available
- stronger guest workflows enabled
- BYOD and onboarding features available
- profiling and posture available
- richer reporting and enforcement models available

### `custom`

Use `custom` when:

- the operator knows exactly what they want
- the product should stop pushing an opinionated default

Even in `custom`, the product should still block impossible combinations.

## UI Behavior

The admin UI should present feature state clearly.

Every major feature section should show:

- state badge
- short reason
- dependency summary
- what is needed to unlock it

Examples:

- `Wireless AP Mode: blocked - requires a real radio interface`
- `Full AI: warned - enterprise profile recommended, provider configured`
- `Sponsor Approval: blocked - email delivery is not configured`
- `Runtime Shaping: degraded - enabled with reduced probe cadence on lite profile`

The UI should prefer:

- disable and explain when impossible
- warn and allow when risky but still usable
- degrade automatically when the product can reduce resource cost safely
- show the hardware scaling mode and active gates next to deployment profile status

## Config Validation Behavior

The config layer should enforce impossible combinations, not just the UI.

Examples of invalid states:

- `wireless.enabled: true` on a VM without a detected radio
- full AI enabled with no provider endpoint or model
- onboarding CA enabled with no CA material
- posture enabled with no profiling or compliance source
- shaping enabled with no downstream shaping interface

Examples of warning states:

- full AI on a low-memory target
- active RADIUS upstream probes on a very constrained VM
- local Wi-Fi plus shaping plus heavy EAP on a small appliance

## Runtime Degrade Rules

Some features can protect the platform by degrading themselves.

Examples:

- reduce recommendation input depth on small targets
- shorten dashboard analytics windows
- reduce active health probe frequency
- cap retention for alerts or session analytics
- disable deep profiling collectors when memory pressure is high

This is better than a binary all-or-nothing product where every tier pays the same runtime cost.

## Implementation Model

The next evolution should introduce a first-class feature evaluator, for example:

- `FeatureCatalog`
- `FeatureRequirement`
- `FeatureCapabilityEvaluator`
- `EffectiveFeatureState`

The evaluator should return:

- `state`
- `reason`
- `required_dependencies`
- `recommended_profile`
- `recommended_hardware`

That result can drive:

- dashboard visibility
- Access Settings badges and warnings
- config validation
- runtime service startup decisions
- packaging guidance

## Recommended Delivery Phases

### Phase 1

Extend the existing profile system into a generic feature capability evaluator for:

- wireless local AP mode
- runtime shaping
- AI mode
- telemetry
- upstream AAA probe behavior

Phase 1 also introduces the first production-grade validation gates:

- virtual local wireless requires `deployment.hardware.wireless_passthrough: true`
- full AI mode requires both `ailite.endpoint` and `ailite.model`
- Access Settings should preview capability state before save

### Phase 2

Add stronger guest workflow controls and runtime:

- self-registration
- sponsor approval
- portal transport dependencies

Phase 2 now includes production-grade guest workflow runtime under `portal.guest_workflows`:

- `self_registration_enabled`
- `sponsor_approval_enabled`
- `invite_delivery`
- `approval_delivery`
- SMTP transport settings for email delivery
- SMS provider and endpoint settings for text delivery

Phase 2 runtime now covers:

- self-registration from the captive portal
- sponsor approval links delivered by email or SMS
- local guest credential minting after approval
- portal completion on the original client once approval lands
- operator visibility and manual approve or reject actions in the admin UI
- audit log and alert generation when delivery fails

Phase 2 validation rules:

- lite profile blocks self-registration, sponsor approval, and invite delivery
- self-registration requires `portal.enabled`, `portal.local_fallback`, and `portal.branding`
- sponsor approval requires self-registration plus a valid delivery transport
- email invite or approval delivery requires SMTP host, port, and sender
- SMS invite or approval delivery requires provider and HTTP or HTTPS endpoint

### Phase 3

Add enterprise feature gating:

- onboarding
- certificate workflows
- profiling
- posture
- richer reporting

Phase 3 adds production-safe config controls under:

- `onboarding.device_inventory_enabled`
- `onboarding.portal_enabled`
- `onboarding.certificate_enrollment_enabled`
- `onboarding.eap_tls_enabled`
- `onboarding.ca_mode`
- `onboarding.ca_cert_path`
- `onboarding.ca_key_path`
- `onboarding.ca_enrollment_url`
- `profiling.mac_inventory_enabled`
- `profiling.passive_enabled`
- `profiling.poll_interval_seconds`
- `profiling.retention_hours`
- `profiling.posture_enabled`
- `profiling.mdm_provider`
- `profiling.mdm_endpoint`
- `profiling.compliance_webhook`
- `profiling.remediation_enabled`

Phase 3 capability preview now evaluates:

- `device_registration_inventory`
- `onboarding_portal`
- `certificate_enrollment`
- `eap_tls_onboarding`
- `passive_profiling`
- `posture_checks`

Phase 3 validation rules:

- lite blocks device inventory, onboarding portal, passive profiling, and EAP-TLS onboarding
- onboarding portal requires `portal.enabled`, an identity path, device inventory, and a declared CA mode
- certificate enrollment is enterprise-only and requires full CA configuration
- EAP-TLS onboarding requires certificate enrollment, `radius.eap.default_type: tls`, and CRL or OCSP revocation enforcement
- passive profiling requires MAC inventory and a poll interval of at least 30 seconds
- posture checks are enterprise-only and require MAC inventory plus an MDM endpoint or compliance webhook

Current runtime implementation after Phase 3:

- the portal now exposes a live onboarding flow with device registration and certificate download
- device inventory is populated from portal observation, explicit onboarding registration, and passive DHCP lease profiling
- passive profiling records hostname, DHCP client ID, DHCP fingerprint, user-agent, LLDP, CDP, MAC OUI, profile risk score, and risk reasons; remediation can quarantine high-risk active sessions with `quarantine-profile-risk`
- internal CA mode issues client certificates, stores bundle metadata in the appliance database, supports local revoke and renew, and can emit an internal-CA CRL
- the admin UI now exposes a `Devices` page for inventory and certificate retrieval
- telemetry runs live MDM or compliance-webhook posture synchronization when those integrations are enabled
- posture enforcement updates active sessions by mapping non-compliant devices into quarantine policy

This phase now delivers real BYOD and profiling runtime on top of the earlier gating work. It still assumes vendor-neutral onboarding and posture inputs rather than claiming feature parity with every commercial onboarding suite.

### Phase 4

Add integration-aware gating:

- MDM or UEM
- SIEM or webhooks
- external controller-aware workflows
- delegated admin and RBAC

Phase 4 adds production-safe config controls under:

- `profiling.mdm_sync_enabled`
- `profiling.mdm_cache_hours`
- `integrations.admin_sso.*`
- `integrations.siem.*`
- `integrations.controller.*`
- `governance.delegated_admin_enabled`
- `governance.rbac_mode`
- `governance.external_groups_enabled`
- `governance.multi_tenant_enabled`
- `governance.tenant_claim`

Phase 4 capability preview now evaluates:

- `mdm_uem_integration`
- `siem_webhook_export`
- `controller_automation`
- `admin_sso`
- `delegated_admin_rbac`
- `multi_tenant_governance`

Phase 4 validation rules:

- authoritative MDM or UEM sync is enterprise-only and requires provider, endpoint, and cache window
- posture can rely on MDM only when MDM sync is explicitly enabled, otherwise it must use a compliance webhook
- admin SSO requires provider, issuer or metadata URL, client ID, and redirect URL; an optional client secret env can be supplied for confidential-client OIDC deployments
- SIEM export requires provider, endpoint, API key env, and positive batch size
- controller automation requires platform, endpoint, API token env, sync mode, and the external AP model
- delegated admin requires admin SSO or LDAP, and external-group RBAC requires a groups claim or LDAP group mapping
- multi-tenant governance is enterprise-only and requires delegated admin; when admin SSO is active it also needs a tenant claim

Current runtime implementation after Phase 4:

- the admin API supports OIDC and SAML admin SSO with short-lived internal admin sessions and break-glass token fallback
- OIDC uses state, nonce, PKCE, and ID token validation against discovery metadata
- SAML publishes service-provider metadata, generates signing material on first run, validates assertions against IdP metadata, and maps assertion attributes into delegated-admin roles
- delegated admin now resolves live runtime roles (`super_admin`, `ops_admin`, `guest_admin`, `read_only`) from cached admin principals and SSO group claims
- admin principals can be reviewed and updated from the `Admin Access` page in the UI
- multi-tenant governance now scopes guest workflow, device inventory, certificate download, and session operations by tenant-aware admin sessions
- the telemetry service exports audit logs and alerts to `webhook`, `splunk-hec`, or `elastic`
- controller automation now runs as a live background loop; `monitor` and `pull-config` read controller state while `push-config` sends appliance policy to the configured endpoint
- controller sync payloads include adapter capabilities and a desired-state hash; Cisco ISE ERS, Aruba Central Classic, Juniper Mist site WLANs, Ruckus SmartZone v13_1, FortiGate CMDB VAPs, MikroTik RouterOS RADIUS/WiFi profiles, and UniFi Network WiFi broadcasts have native read/reconcile clients, while generic REST uses its declared sync contract
- the admin API and dashboard expose the controller adapter catalog, selected adapter readiness, token environment presence, site or network requirements, and setup warnings
- operators can preview pull or push requests, run a read-only drift check, and execute a confirmation-locked push; manual results feed runtime counters and durable integration history
- export and controller runtime state are stored in `runtime_status`
- failed deliveries or controller sync errors degrade only the affected integration path and do not block authentication, session handling, or portal traffic
- the dashboard surfaces live admin SSO, SIEM export, and controller automation state, provider, endpoint or redirect target, and last runtime message for operators

This phase now delivers real runtime integrations for the declared production paths while still being honest about product boundaries. Cisco ISE, Aruba Central, Juniper Mist, Ruckus SmartZone, FortiGate, MikroTik, and UniFi execute provider-native resource operations; generic REST remains a vendor-neutral sync contract rather than a promise of one-to-one feature parity with every vendor controller API.

Release certification uses `scripts/vendor-certification-lab.sh` one pack at a time. Its required gates cover product vendor identity, runtime catalog presence, reply rendering, and optional live RADIUS, packet capture, device, controller, upgrade, and rollback evidence. CI validates the harness itself; real hardware evidence remains a release-lab responsibility.

### Phase 5

Add automatic hardware scaling modes:

- `deployment.hardware.storage_gb`
- CPU/RAM/storage-based `lite`, `branch`, and `enterprise` mode selection
- recommended retention, RADIUS session, recommendation, AP model, and controller sync limits
- active hardware gates applied to feature capability results
- dashboard and Access Settings visibility for scaling mode and active gates

Phase 5 capability preview now evaluates hardware scaling after normal feature dependency checks, so selected enterprise features are blocked on branch hardware even when their external dependencies are otherwise present.

Phase 5 validation rules:

- negative `deployment.hardware.storage_gb` is rejected
- selected profiles above the declared hardware scaling mode return warnings
- enterprise-only posture, MDM, HA, and multi-tenant controls are gated on branch hardware
- heavyweight branch and enterprise workflows are gated on lite hardware

## Product Positioning Outcome

If this framework is implemented cleanly, AegisNAS can become:

- simple enough for lab VMs
- safe enough for low-power appliances
- strong enough for real branch deployments
- expandable enough for enterprise NAC growth

That is a better product direction than trying to clone each vendor suite one feature page at a time.
