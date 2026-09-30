# Admin API Guide

RadSec upstream status and history include `transport`, `radsec_port`,
`tls_version`, `tls_cipher_suite`, `tls_alpn`, `peer_subject`, `peer_issuer`,
`peer_serial`, and `peer_not_after`. RADIUS-client list responses return
`secret_set`, `inline_secret_set`, `secret_ref_set`, and
`secret_ref_fingerprint`; they never return shared-secret values. RadSec
TLS-PSK credential views return presence flags and fingerprints, never secret
values or raw secret references. See
[radsec.md](radsec.md) and [secret-providers.md](secret-providers.md).

This guide is the operator and integration entry point for the AegisNAS admin API.

Use it when you want to:

- inspect the live API contract
- understand bearer-auth expectations
- understand which admin roles can call which endpoint families
- point external tools at a stable OpenAPI document

Use this guide together with:

- [Operations Guide](operations.md)
- [Upgrade Rollback Runbook](upgrade-rollback-runbook.md)
- [HA Active/Standby Runbook](ha-active-standby-runbook.md)

## OpenAPI Endpoint

The appliance now serves a live OpenAPI document at:

```text
/api/v1/openapi.json
```

Examples:

```bash
curl -fsS http://127.0.0.1:8083/api/v1/openapi.json | jq '.info, .servers'
```

Or from the admin UI:

1. sign in
2. open `Backups`
3. select `Download OpenAPI JSON`

## Deployment Scaling Status

System status and draft settings evaluation include the deployment profile, hardware hints, capability states, and automatic scaling plan:

```text
/api/v1/system/status
/api/v1/system/settings/evaluate
```

The `deployment.scaling` object reports the effective Lite, Branch, or Enterprise hardware mode, whether the selected profile fits the declared hardware, recommended retention and limits, and active gating actions. Use it before enabling heavyweight features on low-spec hardware.

## Production Readiness Endpoint

Before production sign-off, run the deployment readiness report:

```text
/api/v1/system/production-readiness
```

Example:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/production-readiness | jq '.status, .checks[] | select(.status != "passed")'
```

The report checks config validation, declared hardware scaling, AegisNAS vendor identity and placeholder PEN use, dictionary release profile integrity, product dictionary detection, NAS-0060 vendor mapping certification, NAS-0061 Cisco-family pack certification, NAS-0062 Aruba/HPE-family pack certification, NAS-0063 Juniper/ERX/Extreme/Mist pack certification, NAS-0064 Ruckus/ICX pack certification, NAS-0065 Fortinet/Palo Alto pack certification, NAS-0066 Meraki/UniFi/OpenWiFi cloud pack certification, active vendor compatibility packs, deployed NAS profile coverage, active feature gates, controller readiness, and vendor runtime evidence from live RADIUS/CoA counters. A short summary also appears in `/api/v1/system/status` as `production_readiness`.

## Outbound Dynamic Authorization

RFC 5176 CoA and Disconnect client state is exposed through:

```text
GET  /api/v1/system/dac-client
GET  /api/v1/system/nas-ownership
GET  /api/v1/system/dac-handoff
POST /api/v1/system/dac-client/preview
POST /api/v1/system/dac-client/send
POST /api/v1/system/dac-client/enqueue
POST /api/v1/system/dac-client/replay
POST /api/v1/system/dac-client/cancel
POST /api/v1/system/dac-client/retry
GET  /api/v1/system/dac-client/history
```

Read-only roles can inspect client policy and history. `ops_admin` and
`super_admin` can preview, send, enqueue, replay, cancel, and retry confirmed
requests. Requests may target a direct NAS or a configured proxy route using
`delivery_mode`, `proxy_route`, `originating_realm`, `proxy_realm`,
`proxy_home_server`, and bounded `proxy_state`. Requests may also include a
neutral vendor dynamic-action intent with `vendor_action`, `vendor_packs`,
`role`, `vlan`, `acl_name`, `bandwidth_profile`, `download_rate_kbps`,
`upload_rate_kbps`, `policy_tag`, and `portal_profile`. Preview responses
include `vendor_action_decision` with selected packs, compiled VSA attributes,
warnings, and blockers. Preview responses also include `ownership_decision`
with the resolved session owner, supported actions, supported transports,
required capabilities, warnings, and blockers. Preview responses also include
`handoff_decision` with the local HA role, effective runtime role, node ID,
lease ID, fencing token evidence, send/queue/replay authority, warnings, and
blockers. History stores target, proxy route metadata, vendor compiler evidence,
NAS ownership evidence, capability decision, HA handoff evidence, status,
Error-Cause, latency, fingerprints, queue state, hashed idempotency keys, and
correlation evidence while redacting sensitive selector values. The report is embedded in
`/api/v1/system/status` as `radius.dac_client`, included in production
readiness as `radius_outbound_dac_client`, and captured in support bundles as
`api/dac-client.json`, `api/nas-ownership.json`, `api/dac-handoff.json`, and
`api/dac-client-history.json`. `GET /api/v1/system/nas-ownership` returns NAS
capability clients, active session owners, stale/unknown counts, ownership
coverage, and supported action/transport evidence for NAS-0046.
`GET /api/v1/system/dac-handoff` returns lease and event evidence for NAS-0047.
See
[outbound-dac-client.md](outbound-dac-client.md).

## TACACS+ Command Authorization

Device-administration TACACS+ state is exposed through:

```text
GET  /api/v1/system/tacacs
POST /api/v1/system/tacacs/evaluate
POST /api/v1/system/tacacs/command-sets
PUT  /api/v1/system/tacacs/command-sets/{name}
```

Read-only roles can inspect TACACS+ status, command sets, recent
authorization decisions, and accounting evidence. `ops_admin` and
`super_admin` can evaluate commands and save command sets. The report is also
embedded in `/api/v1/system/status` as `radius.tacacs`, production readiness as
`tacacs_command_authorization`, support bundles as `api/tacacs.json`, and
Access Settings. See [tacacs-command-authorization.md](tacacs-command-authorization.md).

## Tenant Isolation

Tenant isolation and delegated policy ownership are exposed through:

```text
GET  /api/v1/system/tenant-isolation
POST /api/v1/system/tenant-isolation/evaluate
POST /api/v1/system/tenant-isolation/tenants
PUT  /api/v1/system/tenant-isolation/tenants/{tenant}
POST /api/v1/system/tenant-isolation/resources
```

Read-only roles can inspect tenant isolation status. `ops_admin` and
`super_admin` can save tenant profiles, bind tenant-owned resources, and
evaluate resource access. Tenant-scoped delegated admins can only operate inside
their assigned tenant list. The report is also embedded in
`/api/v1/system/status` as `radius.tenant_isolation`, production readiness as
`tenant_isolation`, support bundles as `api/tenant-isolation.json`, and Access
Settings. See [tenant-isolation-delegation.md](tenant-isolation-delegation.md).

## MAC Authentication Bypass

MAB state, endpoint inventory, and audit history are exposed through:

```text
GET    /api/v1/system/mab
GET    /api/v1/system/mab/endpoints
POST   /api/v1/system/mab/endpoints
PUT    /api/v1/system/mab/endpoints/{mac}
DELETE /api/v1/system/mab/endpoints/{mac}
POST   /api/v1/system/mab/evaluate
```

Read-only roles can inspect MAB state and endpoint records. `ops_admin` and
`super_admin` can create, update, delete, and evaluate endpoint decisions.
`/api/v1/system/status` embeds the report at `identity.mab`, production
readiness includes `mac_authentication_bypass`, and support bundles include
`api/mab.json`.

See [mac-authentication-bypass.md](mac-authentication-bypass.md).

## RadSec Credential Status

Use the RadSec credential report during TLS-PSK staging, mTLS certificate
renewal, and production readiness reviews:

```text
/api/v1/system/radsec-credentials
```

Example:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/radsec-credentials | jq '.status, .summary, .upstream[]?'
```

The report includes inbound mTLS state, upstream mTLS and TLS-PSK peers,
effective TLS-PSK identity, staged/active/expired rotation windows, certificate
warning state, and blocking issues. It is also embedded in
`/api/v1/system/status` as `radius.radsec_credentials` and included in
`/api/v1/system/production-readiness` as the `radsec_credentials` check.

## Vendor Compatibility Endpoint

The appliance exposes the built-in AegisNAS vendor dictionary catalog and semantic registry at:

```text
/api/v1/system/vendor-compatibility
```

Examples:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-compatibility | jq '.summary'
```

Use this endpoint when you want to confirm:

- the active AegisNAS product vendor ID and built-in VSA count
- whether the product vendor ID still uses the lab placeholder and where `dictionary.aegisnas` should be installed
- the active vendor compatibility packs from `radius.vendor.compatibility_packs`
- reversible numeric role mappings from `radius.vendor.role_mappings` for Cambium, Aerohive, D-Link, SonicWall, and ZTE
- validated Extreme tagged and untagged VLAN mappings from `radius.vendor.extended_vlan_mappings`
- allowlisted, role-based Juniper, Huawei, H3C, and Arista AVPair templates from `radius.vendor.avpair_mappings`
- reversible TP-Link portal profile values from `radius.vendor.portal_status_mappings`
- reversible Nomadix role and session-action values from `radius.vendor.session_action_mappings`
- per-role ChilliSpot combined data quotas from `radius.vendor.quota_mappings`
- per-role Nokia decimal service names encoded as BCD from `radius.vendor.service_name_mappings`
- the parsed dictionary coverage matrix through `dictionary_coverage`, including configured or auto-detected FreeRADIUS dictionary imports
- the pinned dictionary release, alias table, firmware scopes, and registry SHA-256 through `dictionary_release_profile`
- the compatibility evidence model through `evidence`, including software-ready, planned, blocked, and external-certification counts
- the same coverage model is available from `aegis-admin scan-radius-dictionaries` for offline JSON/CSV scans of FreeRADIUS dictionary trees
- reply preview responses include normalized ACL intent plus per-pack ACL exports for Cisco AVPair, Aruba/NAS filter rules, AegisNAS ACL rules, and profile-style vendor hints
- the deployed RADIUS client `nas_type` values and their effective reply packs through `client_profiles`
- the current profile coverage, unknown profile list, and fallback count through `profile_summary`
- which semantic policy keys already have product attributes
- which vendor-compatibility areas are implemented versus planned
- which pieces are intended for lite, branch, or enterprise appliances

NAS-0060 exposes a stricter software certification report for the 141
audit-source partial mappings from the pinned FreeRADIUS 3.2.8 registry:

```text
GET  /api/v1/system/vendor-mapping-certification
POST /api/v1/system/vendor-mapping-certification/record
GET  /api/v1/system/vendor-mapping-certification/history
```

The report is derived from the typed registry, compatibility evidence,
semantic policy registry, packet codec coverage, storage ledger, enforcement
owners, API/UI visibility, observability, and release scope. `record` persists
the current source hash, fingerprint, counts, summary JSON, full report JSON,
actor, and timestamp in `vendor_mapping_certification_events`. External
hardware, controller, firmware, FreeRADIUS-on-Linux, HA, performance, soak,
security, production deployment, and customer acceptance proof remains in
[nas-0060-release-certification-checklist.md](nas-0060-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-mapping-certification | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-mapping-certification/record | jq '.event_id, .status'
```

NAS-0061 exposes the Cisco-family software certification report for all 922
Cisco, Airespace/WLC, ASA/VPN, Starent, and Meraki rows from the pinned
FreeRADIUS 3.2.8 registry:

```text
GET  /api/v1/system/cisco-family-pack
POST /api/v1/system/cisco-family-pack/record
GET  /api/v1/system/cisco-family-pack/history
```

The report includes Cisco-AVPair grammar coverage, vendor rollups, capability
rollups, native semantic mappings, typed pass-through mappings, bounded
software evidence, and release scope. `record` persists the current source
hash, fingerprint, counts, summary JSON, full report JSON, actor, and timestamp
in `cisco_family_pack_events`. External Cisco hardware, controller, firmware,
FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment,
and customer acceptance proof remains in
[nas-0061-release-certification-checklist.md](nas-0061-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/cisco-family-pack | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/cisco-family-pack/record | jq '.event_id, .status'
```

NAS-0062 exposes the Aruba/HPE-family software certification report for all 125
Aruba, HP/ArubaOS-Switch, Aerohive/Extreme, and Colubris/MSM rows from the
pinned FreeRADIUS 3.2.8 registry:

```text
GET  /api/v1/system/aruba-family-pack
POST /api/v1/system/aruba-family-pack/record
GET  /api/v1/system/aruba-family-pack/history
```

The report includes policy grammar coverage, vendor rollups, capability
rollups, native semantic mappings, typed pass-through mappings, sensitive
redaction counts, bounded software evidence, and release scope. `record`
persists the current source hash, fingerprint, counts, summary JSON, full
report JSON, actor, and timestamp in `aruba_family_pack_events`. External
ArubaOS, Aruba Central, ClearPass, ArubaOS-Switch, Aerohive/Extreme,
Colubris/MSM, FreeRADIUS-on-Linux, HA, performance, soak, security, production
deployment, and customer acceptance proof remains in
[nas-0062-release-certification-checklist.md](nas-0062-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/aruba-family-pack | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/aruba-family-pack/record | jq '.event_id, .status'
```

NAS-0063 exposes the Juniper/ERX/Extreme/Mist software certification report for
all 260 Juniper, ERX, and Extreme rows from the pinned FreeRADIUS 3.2.8
registry. Juniper Mist is tracked as a Juniper controller/product scope because
the pinned registry has no separate Mist VSA namespace:

```text
GET  /api/v1/system/juniper-extreme-pack
POST /api/v1/system/juniper-extreme-pack/record
GET  /api/v1/system/juniper-extreme-pack/history
```

The report includes Juniper AVPair grammar coverage, ERX subscriber and BNG
normalization, Extreme netlogin and extended VLAN handling, product-scope
rollups, vendor rollups, capability rollups, native semantic mappings, typed
pass-through mappings, sensitive redaction counts, bounded software evidence,
and release scope. `record` persists the current source hash, fingerprint,
counts, summary JSON, full report JSON, actor, and timestamp in
`juniper_extreme_pack_events`. External Junos, ERX/E-Series, ExtremeXOS/Switch
Engine, Mist controller, FreeRADIUS-on-Linux, HA, performance, soak, security,
production deployment, and customer acceptance proof remains in
[nas-0063-release-certification-checklist.md](nas-0063-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/juniper-extreme-pack | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/juniper-extreme-pack/record | jq '.event_id, .status'
```

NAS-0064 exposes the Ruckus/ICX software certification report for all 97 Ruckus
and Foundry rows from the pinned FreeRADIUS 3.2.8 registry. Foundry is tracked
as the Ruckus ICX/FastIron switch product scope:

```text
GET  /api/v1/system/ruckus-icx-pack
POST /api/v1/system/ruckus-icx-pack/record
GET  /api/v1/system/ruckus-icx-pack/history
```

The report includes Ruckus FlexAuth grammar, DPSK and subscriber redaction,
WLAN, guest, QoS, quota, NAT pool, mobile-core, accounting, posture, cluster,
domain, SCI context, ICX command authorization, access-list, 802.1X lookup,
voice policy, product-scope rollups, vendor rollups, capability rollups, native
semantic mappings, typed pass-through mappings, bounded software evidence, and
release scope. `record` persists the current source hash, fingerprint, counts,
summary JSON, full report JSON, actor, and timestamp in
`ruckus_icx_pack_events`. External Ruckus controller, ICX/FastIron,
FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and
customer acceptance proof remains in
[nas-0064-release-certification-checklist.md](nas-0064-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/ruckus-icx-pack | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/ruckus-icx-pack/record | jq '.event_id, .status'
```

NAS-0065 exposes the Fortinet/Palo Alto software certification report for all
42 Fortinet and PaloAlto rows from the pinned FreeRADIUS 3.2.8 registry:

```text
GET  /api/v1/system/fortinet-paloalto-pack
POST /api/v1/system/fortinet-paloalto-pack/record
GET  /api/v1/system/fortinet-paloalto-pack/history
```

The report includes Fortinet group, VDOM, tenant, interface, SSID, AP,
FortiAuthenticator challenge/token redaction, web filter, application control,
FortiWAN AVPair, host-port AVPair, FortiDeceptor/FDD, FPC role, Palo Alto
PAN-OS admin role/domain, User-ID, GlobalProtect, Panorama, product-scope
rollups, vendor rollups, capability rollups, native semantic mappings, typed
pass-through mappings, bounded software evidence, and release scope. `record`
persists the current source hash, fingerprint, counts, summary JSON, full
report JSON, actor, and timestamp in `fortinet_paloalto_pack_events`. External
Fortinet appliances/controllers, PAN-OS, GlobalProtect, Panorama,
FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and
customer acceptance proof remains in
[nas-0065-release-certification-checklist.md](nas-0065-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/fortinet-paloalto-pack | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/fortinet-paloalto-pack/record | jq '.event_id, .status'
```

NAS-0066 exposes the Meraki/UniFi/OpenWiFi cloud-controller software
certification report for all 4 Meraki rows and 1 OpenWiFi row from the pinned
FreeRADIUS 3.2.8 registry plus the 2 AegisNAS-runtime UBNT rate rows used by
UniFi deployments:

```text
GET  /api/v1/system/cloud-controller-pack
POST /api/v1/system/cloud-controller-pack/record
GET  /api/v1/system/cloud-controller-pack/history
```

The report includes Meraki device, network, AP, and AP-tag telemetry, OpenWiFi
AP MAC accounting identity, UniFi UBNT downstream/upstream rate parser and
renderer state, controller product-scope rollups, vendor rollups, capability
rollups, native semantic mappings, bounded software evidence, and release
scope. `record` persists the current source hash, fingerprint, counts, summary
JSON, full report JSON, actor, and timestamp in
`cloud_controller_pack_events`. External Meraki Dashboard, UniFi Network, TIP
OpenWiFi OWGW/uCentral, access point, gateway, switch, appliance,
FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and
customer acceptance proof remains in
[nas-0066-release-certification-checklist.md](nas-0066-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/cloud-controller-pack | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/cloud-controller-pack/record | jq '.event_id, .status'
```

NAS-0067 exposes the Cambium/TP-Link/D-Link access-vendor software
certification report for all 49 access rows from the pinned FreeRADIUS 3.2.8
registry:

```text
GET  /api/v1/system/access-vendor-pack
POST /api/v1/system/access-vendor-pack/record
GET  /api/v1/system/access-vendor-pack/history
```

The report includes Cambium cnMaestro/ePMP/PMP role, VLAN, quota, QoS,
walled-garden, and TLV accounting coverage, TP-Link Omada rate/site/group,
portal, command, and authentication-key redaction coverage, D-Link user-level,
bandwidth, priority, VLAN, ACL profile, ACL rule, and ACL script coverage,
product-scope rollups, vendor rollups, capability rollups, native semantic
mappings, bounded software evidence, and release scope. `record` persists the
current source hash, fingerprint, counts, summary JSON, full report JSON,
actor, and timestamp in `access_vendor_pack_events`. External Cambium
cnMaestro/ePMP/PMP, TP-Link Omada, D-Link/Nuclias, access point, switch,
gateway, FreeRADIUS-on-Linux, HA, performance, soak, security, production
deployment, and customer acceptance proof remains in
[nas-0067-release-certification-checklist.md](nas-0067-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/access-vendor-pack | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/access-vendor-pack/record | jq '.event_id, .status'
```

NAS-0068 exposes the Huawei/H3C/ZTE broadband-vendor software certification
report for all 308 broadband rows from the pinned FreeRADIUS 3.2.8 registry:

```text
GET  /api/v1/system/broadband-vendor-pack
POST /api/v1/system/broadband-vendor-pack/record
GET  /api/v1/system/broadband-vendor-pack/history
```

The report includes Huawei BRAS/BNG subscriber state, QoS, address pool,
route, NAT/translation, portal, command authorization, accounting, charging,
multicast, WLAN/AP, tenant/domain, and redacted credential evidence; H3C
Comware/iMC/BRAS role, group, portal, ITA policy, QoS, NAT, subscriber, DNS,
VRF, multicast, accounting, and device evidence; and ZTE PPPoE portal, QoS,
IPv4/IPv6 SCR rates, privilege role, multicast, tunnel, DNS, domain, VPN, and
subscriber evidence. `record` persists the current source hash, fingerprint,
counts, summary JSON, full report JSON, actor, and timestamp in
`broadband_vendor_pack_events`. External Huawei, H3C, ZTE, FreeRADIUS-on-Linux,
HA, performance, soak, security, production deployment, and customer acceptance
proof remains in
[nas-0068-release-certification-checklist.md](nas-0068-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/broadband-vendor-pack | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/broadband-vendor-pack/record | jq '.event_id, .status'
```

NAS-0069 exposes the Nokia/Alcatel-Lucent service-router software
certification report for all 334 Nokia, Alcatel, Alcatel-ESAM,
Alcatel-Lucent-Service-Router, and ALU-AAA rows from the pinned FreeRADIUS
3.2.8 registry:

```text
GET  /api/v1/system/nokia-alu-pack
POST /api/v1/system/nokia-alu-pack/record
GET  /api/v1/system/nokia-alu-pack/history
```

The report covers Nokia AVPair/profile/service-name BCD handling; Alcatel AAT
address, QoS, and filter attributes; Alcatel ESAM VRF, VLAN, QoS, DHCP, and
PPPoE evidence; ALU SR OS subscriber, SLA/QoS, route, IPv4/IPv6, delegated
prefix, NAT/translation, portal, WLAN, ACL, accounting, charging, and CoA
lifecycle semantics; and ALU-AAA access-rule, AVPair, service-profile,
location, event, NAS identity, and redacted mobile-auth evidence. `record`
persists the current source hash, fingerprint, counts, summary JSON, full
report JSON, actor, and timestamp in `nokia_alu_pack_events`. External Nokia
SR OS, Alcatel AAT, Alcatel ESAM, ALU-AAA, FreeRADIUS-on-Linux, HA,
performance, soak, security, production deployment, and customer acceptance
proof remains in
[nas-0069-release-certification-checklist.md](nas-0069-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/nokia-alu-pack | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/nokia-alu-pack/record | jq '.event_id, .status'
```

NAS-0070 exposes the MikroTik RouterOS software certification report for all
32 MikroTik rows from the pinned FreeRADIUS 3.2.8 registry:

```text
GET  /api/v1/system/mikrotik-pack
POST /api/v1/system/mikrotik-pack/record
GET  /api/v1/system/mikrotik-pack/history
```

The report covers RouterOS PPP/PPPoE quota and gigawords fields, queue
rate-limit grammar, group/profile role assignment, firewall address-list and
switching-filter ACL profile references, tenant realm and mark-id selectors,
hotspot advertise URL/interval hints, IPv4 host and IPv6 delegated-pool hints,
CAPsMAN wireless forwarding, VLAN, encryption, signal, comment, DHCP option
evidence, wireless key redaction, and RFC 5176 CoA/Disconnect lifecycle
semantics. `record` persists the current source hash, fingerprint, counts,
summary JSON, full report JSON, actor, and timestamp in
`mikrotik_pack_events`. External RouterOS, CAPsMAN, PPP/PPPoE, hotspot,
FreeRADIUS-on-Linux, CoA/Disconnect, HA, performance, soak, security,
production deployment, and customer acceptance proof remains in
[nas-0070-release-certification-checklist.md](nas-0070-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/mikrotik-pack | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/mikrotik-pack/record | jq '.event_id, .status'
```

NAS-0071 exposes the enterprise switching vendor software certification report
for all 69 pinned 3Com, Dell EMC, EqualLogic, Brocade, Force10, Foundry,
Arista, and Extreme rows from the pinned FreeRADIUS 3.2.8 registry:

```text
GET  /api/v1/system/switching-vendor-pack
POST /api/v1/system/switching-vendor-pack/record
GET  /api/v1/system/switching-vendor-pack/history
```

The report covers switch role and privilege mapping, command authorization
context, VLAN and fabric selectors, ACL/profile assignment, vendor AVPair
grammar, QoS, captive portal and WebAuth hints, session remediation, VRF,
device/posture context, administrative identity, and accounting evidence.
`record` persists the current source hash, fingerprint, counts, summary JSON,
full report JSON, actor, and timestamp in `switching_vendor_pack_events`.
External switch firmware, controller APIs, FreeRADIUS-on-Linux, CoA/Disconnect,
HA, performance, soak, security, production deployment, and customer acceptance
proof remains in
[nas-0071-release-certification-checklist.md](nas-0071-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/switching-vendor-pack | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/switching-vendor-pack/record | jq '.event_id, .status'
```

NAS-0072 exposes the long-tail typed namespace software certification report
for all 1,126 pinned rows across 92 remaining in-corpus FreeRADIUS vendor
namespaces:

```text
GET  /api/v1/system/long-tail-namespaces
POST /api/v1/system/long-tail-namespaces/record
GET  /api/v1/system/long-tail-namespaces/history
```

The report covers deterministic dictionary classification, neutral semantics
for role, VLAN, ACL/filter, bandwidth, quota, portal, address, route, VRF,
posture, tenant, controller, certificate, accounting, and CoA evidence,
bounded typed pass-through for vendor-specific rows, and redaction for token,
password, key, secret, certificate, challenge, and private material. `record`
persists the current source hash, fingerprint, counts, summary JSON, full
report JSON, actor, and timestamp in `long_tail_namespace_events`. External
hardware, controller, firmware, FreeRADIUS-on-Linux, CoA/Disconnect, HA,
performance, soak, security, production deployment, compliance, and customer
acceptance proof remains in
[nas-0072-release-certification-checklist.md](nas-0072-release-certification-checklist.md).

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/long-tail-namespaces | jq '.report.summary'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/long-tail-namespaces/record | jq '.event_id, .status'
```

NAS-0073 exposes the governed software intake path for authoritative vendor
dictionaries that are outside the pinned FreeRADIUS corpus:

```text
GET  /api/v1/system/external-vendor-intake
POST /api/v1/system/external-vendor-intake/preview
POST /api/v1/system/external-vendor-intake/record
GET  /api/v1/system/external-vendor-intake/history
```

`GET` returns required provenance fields, accepted licenses, parser limits,
supported wire types, and recent evidence. `preview` parses a submitted
FreeRADIUS-style dictionary and classifies every VSA by vendor, PEN, wire type,
semantic family, packet handling, redaction, policy state, and release scope.
`record` persists the bounded report in `external_vendor_intake_events`; raw
dictionary text is fingerprinted but not stored. Read-only roles can inspect
status and history. `ops_admin` and `super_admin` can preview and record. See
[external-vendor-intake.md](external-vendor-intake.md).

The API also provides a non-mutating reply preview endpoint:

```text
/api/v1/system/vendor-reply-preview
```

Example:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"nas_type":"aruba","role":"guest","vlan":20,"download_kbps":50000,"upload_kbps":20000}' \
  http://127.0.0.1:8083/api/v1/system/vendor-reply-preview | jq '.effective_packs, .attributes'
```

Use this before introducing a new AP, switch, or controller profile so you can verify the exact reply attributes and fallback warnings without changing live policy.

## Tagged VLAN And QinQ Policy

NAS-0054 exposes the vendor-neutral VLAN policy compiler at:

```text
GET  /api/v1/system/vlan-policy
POST /api/v1/system/vlan-policy/preview
POST /api/v1/system/vlan-policy/compile
POST /api/v1/system/vlan-policy/decompile
GET  /api/v1/system/vlan-policy/history
```

Read-only roles may inspect, preview, compile, and decompile because these
operations do not change local bridge, hostapd, controller, or NAS state.
Responses include compiler version, effective data VLAN, voice VLAN, tagged
VLANs, pool choice, fallback/auth-fail VLANs, QinQ intent, generated
attributes, diagnostics, RFC list, and a SHA-256 fingerprint. Evidence is stored
in `vlan_policy_events`, summarized in `/api/v1/system/status` as
`radius.vlan_policy`, checked by production readiness as
`tagged_vlan_qinq_policy`, and captured in support bundles as
`api/vlan-policy.json` and `api/vlan-policy-history.json`.

Example:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"role":"voice-device","calling_station_id":"aa:bb:cc:dd:ee:ff","pack_keys":["standard","aegisnas","hp","extreme"]}' \
  http://127.0.0.1:8083/api/v1/system/vlan-policy/compile | jq '.result.attributes'
```

`/api/v1/system/vendor-reply-preview` also accepts `data_vlan`,
`voice_vlan`, `tagged_vlans`, `qinq_outer_vlan`, `qinq_inner_vlan`,
`vlan_pool`, `fallback_vlan`, `auth_fail_vlan`, and `vlan_policy_mode` for
non-mutating per-pack reply previews.

See [Tagged VLAN And QinQ Policy](tagged-vlan-qinq-policy.md).

## Per-Session Route And VRF Policy

NAS-0055 exposes the vendor-neutral route and VRF policy compiler at:

```text
GET  /api/v1/system/route-policy
POST /api/v1/system/route-policy/preview
POST /api/v1/system/route-policy/compile
POST /api/v1/system/route-policy/decompile
GET  /api/v1/system/route-policy/history
```

Read-only roles may inspect, preview, and decompile. `ops_admin` and
`super_admin` may compile because compile records active or withdrawn route
ownership. Responses include compiler version, VRF, route owner, revision,
IPv4/IPv6 route lists, generated standard and vendor attributes, diagnostics,
RFC list, evidence event ID, and a SHA-256 fingerprint.

Evidence is stored in `route_policy_events` and `route_policy_ownership`,
summarized in `/api/v1/system/status` as `radius.route_policy`, checked by
production readiness as `per_session_route_vrf_policy`, and captured in support bundles as
`api/route-policy.json` and `api/route-policy-history.json`.

Example:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"role":"branch-vpn","session_id":"session-1","acct_session_id":"acct-1","pack_keys":["standard","aegisnas","cisco"]}' \
  http://127.0.0.1:8083/api/v1/system/route-policy/compile | jq '.result.attributes'
```

Preview and decompile are evidence-only. They do not update active route
ownership. Compile updates the software ownership ledger, and Accounting Stop
or Accounting-Off withdraws matching active ownership rows.

See [Per-Session Route And VRF Policy](per-session-route-vrf-policy.md).

## IPv4 / IPv6 Pools, DHCPv6, RA, And Prefix Delegation

NAS-0056 exposes the vendor-neutral address policy compiler at:

```text
GET  /api/v1/system/address-policy
POST /api/v1/system/address-policy/preview
POST /api/v1/system/address-policy/compile
POST /api/v1/system/address-policy/decompile
GET  /api/v1/system/address-policy/history
```

Read-only roles may inspect, preview, and decompile. `ops_admin` and
`super_admin` may compile because compile records active or withdrawn address
ownership. Responses include compiler version, selected IPv4/IPv6 address,
IPv4/IPv6 pool names, delegated IPv6 prefix, RA prefix, DHCPv6/RA modes,
generated standard and vendor attributes, diagnostics, RFC list, evidence event
ID, and a SHA-256 fingerprint.

Evidence is stored in `address_policy_events` and
`address_policy_ownership`, summarized in `/api/v1/system/status` as
`radius.address_policy`, checked by production readiness as
`ipv4_ipv6_pool_dhcpv6_ra_pd`, and captured in support bundles as
`api/address-policy.json` and `api/address-policy-history.json`.

Example:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"role":"branch-dualstack","session_id":"session-1","acct_session_id":"acct-1","pack_keys":["standard","aegisnas","cisco","juniper","huawei","mikrotik","nokia"]}' \
  http://127.0.0.1:8083/api/v1/system/address-policy/compile | jq '.result.attributes'
```

Preview and decompile are evidence-only. They do not update active address
ownership. Compile updates the software ownership ledger, and Accounting Stop
or Accounting-Off withdraws matching active ownership rows.

See [IPv4 / IPv6 Pools, DHCPv6, RA, And Prefix Delegation](ipv4-ipv6-pools-dhcpv6-ra-prefix-delegation.md).

## CGNAT, NAT64, And Deterministic Subscriber Translation

NAS-0057 exposes the vendor-neutral translation policy compiler at:

```text
GET  /api/v1/system/translation-policy
POST /api/v1/system/translation-policy/preview
POST /api/v1/system/translation-policy/compile
POST /api/v1/system/translation-policy/decompile
GET  /api/v1/system/translation-policy/history
```

Read-only roles may inspect, preview, and decompile. `ops_admin` and
`super_admin` may compile because compile records active or withdrawn
translation ownership. Responses include compiler version, selected translation
mode, public IPv4 pool, public IPv4 address, private IPv4 prefix, subscriber
IPv6 prefix, NAT64 prefix, deterministic port block, logging profile,
accounting key, generated product and vendor attributes, diagnostics, RFC list,
evidence event ID, and a SHA-256 fingerprint.

Evidence is stored in `translation_policy_events` and
`translation_policy_ownership`, summarized in `/api/v1/system/status` as
`radius.translation_policy`, checked by production readiness as
`cgnat_nat64_deterministic_translation`, and captured in support bundles as
`api/translation-policy.json` and `api/translation-policy-history.json`.

Example:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"role":"branch-dualstack","session_id":"session-1","acct_session_id":"acct-1","pack_keys":["aegisnas","cisco","juniper","huawei","h3c","nokia","starent","erx"]}' \
  http://127.0.0.1:8083/api/v1/system/translation-policy/compile | jq '.result.attributes'
```

Preview and decompile are evidence-only. They do not update active translation
ownership. Compile updates the software ownership ledger, and Accounting Stop
or Accounting-Off withdraws matching active ownership rows.

See [CGNAT, NAT64, And Deterministic Subscriber Translation](cgnat-nat64-deterministic-translation.md).

## Dynamic Subscriber Route Export

NAS-0059 exposes BGP/OSPF subscriber route export at:

```text
GET  /api/v1/system/subscriber-route-export
POST /api/v1/system/subscriber-route-export/preview
POST /api/v1/system/subscriber-route-export/apply
POST /api/v1/system/subscriber-route-export/rollback
GET  /api/v1/system/subscriber-route-export/history
```

Read-only and guest-admin roles may inspect, preview, and list history.
`ops_admin` and `super_admin` may apply and rollback. Responses include the
route ownership input, BGP/OSPF/OSPF3 protocol plan, FRR artifact text, command
preview, withdrawals, diagnostics, snapshots, event history, and fingerprints.

Evidence is stored in `subscriber_route_export_snapshots` and
`subscriber_route_export_events`, summarized in `/api/v1/system/status` as
`radius.subscriber_route_export` and `enforcement.subscriber_route_export`,
checked by production readiness as `dynamic_subscriber_route_export`, and
captured in support bundles as `api/subscriber-route-export.json` and
`api/subscriber-route-export-history.json`.

Live apply is gated by `radius.route_policy.dynamic_routing.apply_enabled`.
Preview, history, readiness, support bundles, and atomic transaction planning
remain available while live apply is disabled.

See [Dynamic Subscriber Route Export](dynamic-subscriber-route-export.md).

## Atomic Enforcement Transactions And Drift Rollback

NAS-0058 exposes the cross-target enforcement coordinator at:

```text
GET  /api/v1/system/enforcement-transactions
POST /api/v1/system/enforcement-transactions/preview
POST /api/v1/system/enforcement-transactions/apply
POST /api/v1/system/enforcement-transactions/drift
POST /api/v1/system/enforcement-transactions/rollback
GET  /api/v1/system/enforcement-transactions/history
```

Read-only and guest-admin roles may inspect, preview, and drift-check.
`ops_admin` and `super_admin` may apply and rollback. Responses include the
ordered target plan, target fingerprints, diagnostics, per-target step results,
drift findings, compensation steps, transaction IDs, and evidence summaries.

Evidence is stored in `enforcement_transactions`,
`enforcement_transaction_steps`, and `enforcement_drift_events`, summarized in
`/api/v1/system/status` as `enforcement.atomic_transactions`, checked by
production readiness as `atomic_enforcement_transactions`, and captured in
support bundles as `api/enforcement-transactions.json` and
`api/enforcement-transactions-history.json`.

See [Atomic Enforcement Transactions And Drift Rollback](atomic-enforcement-transactions.md).

The bounded opaque pass-through policy is exposed at:

```text
/api/v1/system/opaque-passthrough
```

Use this endpoint to confirm the default action is `drop`, review explicit allow rules, inspect packet byte limits, and verify the sensitive standard-attribute denylist before enabling proxy workflows that must preserve unknown vendor attributes.

RADIUS packet hardening is exposed at:

```text
/api/v1/system/radius-hardening
```

RADIUS transport downgrade policy is exposed at:

```text
/api/v1/system/transport-policy
```

Use this endpoint to confirm the effective proxy transport mode, fail-closed
state, default required transport, mixed UDP/RadSec route risks, explicit
route-policy exceptions, and production readiness before enabling upstream AAA
proxy workflows. The same summary appears in `/api/v1/system/status` under
`radius.transport_policy` and in production readiness as
`radius_transport_policy`.

Use this endpoint to confirm malformed-packet rejection, `Message-Authenticator` policy, known-source enforcement, `Proxy-State` limits, replay cache, rate limits, generated FreeRADIUS integrity mode, runtime counters, and recent hardening decisions. The same summary appears in `/api/v1/system/status` under `radius.packet_hardening` and in production readiness as `radius_packet_hardening`.

RADIUS proxy routing is exposed at:

```text
/api/v1/system/proxy-routes
```

Use this endpoint to review the effective multi-realm route table, default route behavior, route-to-server bindings, pool strategy, status-check policy, and warnings before generating or deploying FreeRADIUS configuration. The same summary appears in `/api/v1/system/status` under `radius.proxy_routes` and in production readiness as `radius_proxy_routes`.

Proxy loop and attribute policy is exposed at:

```text
/api/v1/system/proxy-policy
```

Use this endpoint to confirm loop-marker enforcement, route trust realms, standard and vendor allow/deny selectors, rewrite rules, generated FreeRADIUS `pre-proxy` / `post-proxy` coverage, and production readiness before enabling upstream proxy workflows. The same summary appears in `/api/v1/system/status` under `radius.proxy_policy` and in production readiness as `radius_proxy_policy`.

Durable proxy accounting spool state is exposed at:

```text
/api/v1/system/accounting-spool
/api/v1/system/accounting-spool?status=queued&limit=100
/api/v1/system/accounting-spool?record_id=<record-id>
```

Use these endpoints to review queued, retrying, sent, poison, and expired accounting records plus replay attempts. Manual replay is available to `ops_admin` and `super_admin`:

```text
POST /api/v1/system/accounting-spool/replay
```

The same summary appears in `/api/v1/system/status` under `radius.accounting_spool` and in production readiness as `radius_accounting_spool`.

Durable local accounting ingest spool state is exposed at:

```text
/api/v1/system/accounting-ingest-spool
/api/v1/system/accounting-ingest-spool?status=queued&limit=100
/api/v1/system/accounting-ingest-spool?record_id=<record-id>
```

Use these endpoints to review local accounting records that were persisted
before ledger apply, retry attempts, poison records, expired records, queue
utilization, and loss-SLO breaches. Manual replay is available to `ops_admin`
and `super_admin`:

```text
POST /api/v1/system/accounting-ingest-spool/replay
```

The same summary appears in `/api/v1/system/status` under
`radius.accounting_ingest_spool`, in production readiness as
`radius_accounting_ingest_spool`, and in support bundles as
`api/accounting-ingest-spool.json`. See
[accounting-ingest-spool-replay.md](accounting-ingest-spool-replay.md).

FreeRADIUS SQL accounting reconciliation is exposed at:

```text
/api/v1/system/sql-accounting
/api/v1/system/sql-accounting?status=pending&limit=100
```

Use these endpoints to review `radacct`, `radpostauth`, pending/stale/error
rows, reconciliation history, and the standard accounting attributes currently
mapped into AegisNAS sessions. Manual reconciliation is available to
`ops_admin` and `super_admin`:

```text
POST /api/v1/system/sql-accounting/reconcile
```

The same summary appears in `/api/v1/system/status` under
`radius.sql_accounting`, in production readiness as `radius_sql_accounting`,
and in support bundles as `api/sql-accounting.json`. See
[freeradius-sql-accounting.md](freeradius-sql-accounting.md).

Accounting idempotency and ordering is exposed at:

```text
/api/v1/system/accounting-ordering
/api/v1/system/accounting-ordering?status=pending&session_key=sess-1&limit=100
```

Use these endpoints to review `radius_accounting_events`, duplicate packet
suppression, pending/stale/error events, reordered packet merges, late Stop
merges, and replay readiness. Manual replay is available to `ops_admin` and
`super_admin`:

```text
POST /api/v1/system/accounting-ordering/replay
```

The same summary appears in `/api/v1/system/status` under
`radius.accounting_ordering`, in production readiness as
`radius_accounting_ordering`, and in support bundles as
`api/accounting-ordering.json`. See
[accounting-idempotency-ordering.md](accounting-idempotency-ordering.md).

64-bit accounting counters and gigaword rollover are exposed at:

```text
/api/v1/system/accounting-counters
```

Use this endpoint to review normalized `Acct-Input-Octets`,
`Acct-Input-Gigawords`, `Acct-Output-Octets`, `Acct-Output-Gigawords`,
maximum 64-bit totals, rollover evidence, reset evidence, and overflow status.
The same summary appears in `/api/v1/system/status` under
`radius.accounting_counters`, in production readiness as
`radius_accounting_counters`, and in support bundles as
`api/accounting-counters.json`. See
[accounting-counters-gigawords.md](accounting-counters-gigawords.md).

IPv6, delegated-prefix, and route accounting is exposed at:

```text
/api/v1/system/accounting-ip
/api/v1/system/accounting-ip?validation_status=invalid&limit=100
/api/v1/system/accounting-ip?session_key=sess-1&limit=100
```

Use this endpoint to review `Framed-IP-Address`,
`Framed-IPv6-Address`, `Framed-IPv6-Prefix`, `Framed-Interface-Id`,
`Delegated-IPv6-Prefix`, `Framed-Route`, `Framed-IPv6-Route`, active and
closed assignment rows, invalid prefix/route evidence, and current session
mirroring. The same summary appears in `/api/v1/system/status` under
`radius.accounting_ip`, in production readiness as `radius_accounting_ip`, and
in support bundles as `api/accounting-ip.json`. See
[accounting-ipv6-routes.md](accounting-ipv6-routes.md).

Multi-service accounting correlation is exposed at:

```text
/api/v1/system/accounting-services
/api/v1/system/accounting-services?status=conflict&limit=100
/api/v1/system/accounting-services?parent_session_key=sess-1&limit=100
```

Use this endpoint to review `Acct-Multi-Session-Id`, `Acct-Link-Count`,
`Service-Type`, `Framed-Protocol`, Class-derived service metadata,
parent/child service-leg rows, subscriber service-chain links, bearer and call
leg counts, and conflict evidence. The same summary appears in
`/api/v1/system/status` under `radius.accounting_services`, in production
readiness as `radius_accounting_services`, and in support bundles as
`api/accounting-services.json`. See
[accounting-multi-service-correlation.md](accounting-multi-service-correlation.md).

Charging records, rating, retention, and export integrity are exposed at:

```text
/api/v1/system/accounting-charging
/api/v1/system/accounting-charging?status=closed&export_status=pending&limit=100
/api/v1/system/accounting-charging?cdr_id=<cdr-id>
```

Use this endpoint to review CDR projection from applied accounting events,
rating status, pending/exported counts, integrity mismatch counts, export hash
evidence, and recent export batches. Manual reconcile/rating and export are
available to `ops_admin` and `super_admin`:

```text
POST /api/v1/system/accounting-charging/reconcile
POST /api/v1/system/accounting-charging/export
GET /api/v1/system/accounting-charging/export/download?export_id=<export-id>
```

The same summary appears in `/api/v1/system/status` under
`radius.accounting_charging`, in production readiness as
`radius_accounting_charging`, and in support bundles as
`api/accounting-charging.json`. See
[accounting-charging-rating-export.md](accounting-charging-rating-export.md).

Upstream outage fallback policy is exposed at:

```text
/api/v1/system/fallback-policy
/api/v1/system/fallback-policy?decision=allowed&limit=100
```

Use this endpoint to review monitor/enforce mode, fail-closed state, local and
LDAP eligibility, identity allowlists, outage window limits, audit retention,
and recent hashed fallback decisions. The same summary appears in
`/api/v1/system/status` under `radius.fallback_policy`, in production readiness
as `radius_fallback_policy`, and in support bundles as
`api/fallback-policy.json`. See [radius-fallback-policy.md](radius-fallback-policy.md).

Typed policy expression engine state is exposed at:

```text
/api/v1/system/policy-engine
POST /api/v1/system/policy-engine/validate
POST /api/v1/system/policy-engine/evaluate
```

Use these endpoints to review typed versus legacy policy rules, field and
operator catalogs, retained redacted decisions, policy-set hashes, conflicts,
and explain traces. The same summary appears in `/api/v1/system/status` under
`radius.policy_engine`, in production readiness as `typed_policy_engine`, and
in support bundles as `api/policy-engine.json`. See
[typed-policy-engine.md](typed-policy-engine.md).

Versioned nested policy-set governance is exposed at:

```text
/api/v1/system/policy-sets
/api/v1/system/policy-sets/versions
POST /api/v1/system/policy-sets/versions
POST /api/v1/system/policy-sets/versions/{id}/submit
POST /api/v1/system/policy-sets/versions/{id}/approve
POST /api/v1/system/policy-sets/versions/{id}/reject
POST /api/v1/system/policy-sets/versions/{id}/activate
POST /api/v1/system/policy-sets/versions/{id}/rollback
POST /api/v1/system/policy-sets/versions/{id}/simulate
POST /api/v1/system/policy-sets/versions/{id}/analyze
/api/v1/system/policy-sets/analyses
/api/v1/system/policy-sets/versions/{fromID}/compare/{toID}
```

Use these endpoints to create immutable policy-set versions, submit them for
maker-checker approval, activate approved versions, compare flattened rule
changes, simulate draft decisions, analyze candidate blast radius against
retained replay samples, and roll back to prior approved versions.
The same state appears in `/api/v1/system/status` under `radius.policy_sets`,
inside `/api/v1/system/policy-engine` as `policy_sets`, in production readiness
as `policy_set_governance`, and in support bundles as `api/policy-sets.json`.
Persisted analysis evidence is available in production readiness as
`policy_simulation_analysis` and support bundles as
`api/policy-simulation-analyses.json`. See
[versioned-policy-sets.md](versioned-policy-sets.md) and
[policy-simulation-analysis.md](policy-simulation-analysis.md).

Per-service authorization and subscriber chain evidence is exposed at:

```text
/api/v1/system/subscriber-service-chains
POST /api/v1/system/subscriber-service-chains/preview
POST /api/v1/system/subscriber-service-chains/activate
POST /api/v1/system/subscriber-service-chains/{chainID}/rollback
```

Use these endpoints to preview ordered service intents from the active policy
engine, activate service-chain evidence for a subscriber session, retain
service-level accounting start records, and record rollback events. Stored
history hashes usernames and Calling-Station-Ids. Operators can review the
same summary in `/api/v1/system/status` under
`radius.subscriber_service_chains`, in production readiness as
`subscriber_service_chains`, in support bundles as
`api/subscriber-service-chains.json`, and in Access Settings. See
[subscriber-service-chains.md](subscriber-service-chains.md).

Identity source failover state is exposed at:

```text
/api/v1/system/identity-failover
/api/v1/system/identity-failover?source=ldap-primary&decision=failed&limit=100
```

Use this endpoint to review deterministic local/LDAP source order, circuit
state, split-result policy, stale-cache posture, audit retention, and recent
hashed identity-source decisions. The same summary appears in
`/api/v1/system/status` under `identity.failover`, in production readiness as
`identity_source_failover`, and in support bundles as
`api/identity-failover.json`. See [identity-source-failover.md](identity-source-failover.md).

Active Directory Kerberos and winbind identity state is exposed at:

```text
/api/v1/system/active-directory
/api/v1/system/active-directory?source=active-directory&decision=accepted&component=configuration&limit=100
POST /api/v1/system/active-directory/check
```

Use these endpoints to review effective domain, realm, LDAPS, verifier method,
group cache, recent hashed AD decisions, and recorded health checks. The
`check` operation runs configuration, DNS, Kerberos binary/keytab, and winbind
trust probes where configured and is restricted to `ops_admin` and
`super_admin`. The same summary appears in `/api/v1/system/status` under
`identity.active_directory`, in production readiness as
`active_directory_identity`, and in support bundles as
`api/active-directory.json`. See
[active-directory-kerberos-winbind.md](active-directory-kerberos-winbind.md).

OTP and RADIUS challenge MFA state is exposed at:

```text
/api/v1/system/mfa
/api/v1/system/mfa?decision=denied&method=totp&limit=100
POST /api/v1/system/mfa/enroll
POST /api/v1/system/mfa/verify
POST /api/v1/system/mfa/recovery-codes
```

Use these endpoints to review effective step-up policy, encrypted TOTP
enrollment posture, challenge state, recovery-code inventory, and hashed MFA
audit decisions. Enrollment, verification, and recovery-code rotation are
restricted to `super_admin`. The same summary appears in `/api/v1/system/status`
under `identity.mfa`, in production readiness as `mfa_challenge_otp`, and in
support bundles as `api/mfa.json`. See [mfa-radius-challenge.md](mfa-radius-challenge.md).

Admin WebAuthn/passkey step-up state is exposed at:

```text
GET    /api/v1/system/webauthn
POST   /api/v1/system/webauthn/register/options
POST   /api/v1/system/webauthn/register/finish
DELETE /api/v1/system/webauthn/credentials/{id}
POST   /api/v1/auth/token/start
POST   /api/v1/auth/webauthn/login/options
POST   /api/v1/auth/webauthn/login/finish
```

Use these endpoints to review passkey policy, enabled credentials, pending
challenges, recent hashed audit decisions, and privileged-admin step-up
readiness. Registration and revocation are restricted to `super_admin`.
Token login and admin SSO can require WebAuthn before a short-lived verified
admin session token is minted. The same summary appears in
`/api/v1/system/status` under `identity.webauthn`, in production readiness as
`admin_webauthn_passkeys`, and in support bundles as `api/webauthn.json`. See
[admin-webauthn-passkeys.md](admin-webauthn-passkeys.md).

The extensible EAP method framework is exposed at:

```text
GET  /api/v1/system/eap-framework
POST /api/v1/system/eap-framework/evaluate
GET  /api/v1/system/eap-framework/teap
POST /api/v1/system/eap-framework/teap/evaluate
GET  /api/v1/system/eap-framework/machine-user
POST /api/v1/system/eap-framework/machine-user/evaluate
GET  /api/v1/system/eap-framework/fast-pwd
POST /api/v1/system/eap-framework/fast-pwd/evaluate
GET  /api/v1/system/eap-framework/sim-aka
POST /api/v1/system/eap-framework/sim-aka/evaluate
```

Use these endpoints to inspect the typed EAP catalog, effective PEAP/TTLS/TLS
TEAP, machine/user correlation, FAST, PWD, SIM, AKA, and AKA-prime policy,
method blockers,
identity-source bindings, vendor compatibility profiles, and recent hashed
method decisions. `evaluate`, `teap/evaluate`, `fast-pwd/evaluate`, and
`sim-aka/evaluate` are restricted to `ops_admin` and `super_admin`;
`machine-user/evaluate` follows the same role boundary and can
optionally record audited decisions. The same summaries appear in
`/api/v1/system/status` under `radius.eap_framework`, `radius.eap_teap`,
`radius.eap_machine_user`, `radius.eap_fast_pwd`, and `radius.eap_sim_aka`, in
production readiness as `eap_method_framework`, `teap_method_chaining`,
`eap_machine_user_correlation`, `eap_fast_pwd_methods`, and
`eap_sim_aka_methods`, and in support bundles as `api/eap-framework.json`,
`api/eap-framework-teap.json`, `api/eap-framework-machine-user.json`,
`api/eap-framework-fast-pwd.json`, and `api/eap-framework-sim-aka.json`. See
[eap-method-framework.md](eap-method-framework.md) and
[teap-method-chaining.md](teap-method-chaining.md), plus
[eap-machine-user-correlation.md](eap-machine-user-correlation.md),
[eap-fast-pwd.md](eap-fast-pwd.md), and [eap-sim-aka.md](eap-sim-aka.md).

## Dynamic NAS Client Endpoints

NAS client bootstrap and lifecycle state are exposed through:

```text
POST /api/v1/nas/enroll
GET  /api/v1/system/nas-clients
GET  /api/v1/system/nas-clients/enrollments
POST /api/v1/system/nas-clients/enrollments
POST /api/v1/system/nas-clients/enrollments/{id}/approve
POST /api/v1/system/nas-clients/enrollments/{id}/reject
POST /api/v1/system/nas-clients/enrollments/{id}/revoke
GET  /api/v1/system/nas-clients/templates
POST /api/v1/system/nas-clients/templates
PUT  /api/v1/system/nas-clients/templates/{name}
DELETE /api/v1/system/nas-clients/templates/{name}
```

`POST /api/v1/nas/enroll` is intentionally unauthenticated by admin bearer token, but it requires `X-AegisNAS-Enrollment-Token` or `Authorization: Bearer <token>` matching `radius.dynamic_clients.enrollment_token_ref`. Unknown packet sources discovered by RADIUS hardening may create pending evidence, but the packet is still rejected until an operator approves the client.

The lifecycle APIs return pending, approved, rejected, revoked, and expired enrollments; capability templates; recent events; and dynamic/static inventory counts. The same summary appears in `/api/v1/system/status` under `radius.dynamic_nas_clients` and in production readiness as `dynamic_nas_clients`. See [dynamic-nas-clients.md](dynamic-nas-clients.md).

## Secret Provider Endpoint

Secret-provider readiness is exposed at:

```text
/api/v1/system/secret-providers
```

Use it to confirm `env:` and `file:` references resolve, inline secret material
has been migrated, and provider policy is ready before production sign-off. The
endpoint returns reference fingerprints and status only; it does not return
secret values.

## Database Data-Plane Endpoint

Database backend readiness is exposed at:

```text
/api/v1/system/database
```

Use it to confirm SQLite or PostgreSQL mode, schema version, pool settings, TLS
posture, DSN reference status, and HA readiness. The endpoint reports a DSN
fingerprint only; it never returns the DSN or database password.

## ACL Policy Library

Vendor-neutral dynamic ACL policies use the standard staged configuration workflow:

```text
GET    /api/v1/acl-policies
POST   /api/v1/acl-policies
PUT    /api/v1/acl-policies/{id}
DELETE /api/v1/acl-policies/{id}
POST   /api/v1/validate
POST   /api/v1/apply
```

Each policy stores a stable name, optional vendor inbound/outbound ACL names, a lossless ACL AST, and a flat `acl_rules` compatibility projection. ACL policy changes are included in config revision snapshots and rollback. A vendor reply preview containing only `acl_policy_name` loads an enabled applied policy and reports `acl_policy_loaded: true`; explicit `acl_rules` and optional `acl_ast` remain available for one-off previews.

NAS-0048 makes `acl_ast` the source of truth when it is supplied. The flat rules remain backward-compatible output for `NAS-Filter-Rule`, Cisco `Cisco-AVPair`, Aruba filter rules, AegisNAS ACL VSAs, and profile-style vendor hints. Responses include `acl_ast`, `ast_fingerprint`, `ast_diagnostics`, and `acl_round_trip` so operators can see whether rich intent such as object groups, service groups, applications, URL categories, state, ICMP/TCP fields, DSCP, or time ranges can be represented losslessly by current RADIUS attributes.

ACL AST health and ad hoc normalization are available at:

```text
GET  /api/v1/system/acl-ast
POST /api/v1/system/acl-ast/normalize
```

The status endpoint is read-only evidence for production readiness and support bundles. The normalize endpoint accepts `name`, optional `inbound_acl`, optional `outbound_acl`, optional `rules`, and optional `acl_ast`, then returns normalized AST, compatibility rules, fingerprint, diagnostics, and round-trip status without staging a change. See [acl-ast.md](acl-ast.md) for the AST schema and operator workflow.

NAS-0049 adds certified per-vendor ACL compiler and decompiler endpoints:

```text
GET  /api/v1/system/acl-compilers
POST /api/v1/system/acl-compilers/compile
POST /api/v1/system/acl-compilers/decompile
GET  /api/v1/system/acl-compilers/history
```

`GET /api/v1/system/acl-compilers` returns the compiler catalog, software
certification state, supported attributes, limits, recent evidence, and RFC
scope. `POST /api/v1/system/acl-compilers/compile` accepts the same ACL intent
fields as reply preview plus `pack_keys` and returns per-pack attributes,
FreeRADIUS text, artifact fingerprints, lossless state, diagnostics, and
warnings without applying anything. `POST /api/v1/system/acl-compilers/decompile`
accepts `pack_key`, optional `policy_name`, and vendor ACL attributes, then
returns neutral ACL rules or profile references. `GET
/api/v1/system/acl-compilers/history` lists durable compile/decompile evidence
from `acl_compiler_events`.

Software-certified line-rule compilers exist for standard `NAS-Filter-Rule`,
AegisNAS, Cisco, Aruba, HP/ArubaOS-Switch, D-Link, and Pica8. MikroTik,
Fortinet, Ruckus, Juniper, Huawei, and H3C are explicit profile-reference
compilers. Unsupported packs fail closed when ACL intent is present. See
[acl-compilers.md](acl-compilers.md).

NAS-0050 adds stateful per-session local firewall policy endpoints:

```text
GET  /api/v1/system/runtime-firewall
POST /api/v1/system/runtime-firewall/preview
POST /api/v1/system/runtime-firewall/apply
POST /api/v1/system/runtime-firewall/rollback
GET  /api/v1/system/runtime-firewall/history
```

`GET /api/v1/system/runtime-firewall` returns the current compiled nftables
plan, session coverage, diagnostics, ruleset fingerprint, and recent evidence.
`POST /api/v1/system/runtime-firewall/preview` records a preview event without
changing nftables. `POST /api/v1/system/runtime-firewall/apply` applies the
owned `table inet aegis_runtime` ruleset, stores an active snapshot, and links
the previous snapshot for rollback. `POST /api/v1/system/runtime-firewall/rollback`
restores a selected snapshot, or the newest previous applied snapshot when no
snapshot is specified. `GET /api/v1/system/runtime-firewall/history` lists
runtime firewall snapshots and events.

Runtime firewall status is included in `/api/v1/system/status` under
`enforcement.local_firewall`, production readiness as `stateful_local_firewall`,
and support bundles as `api/runtime-firewall.json` and
`api/runtime-firewall-history.json`. See
[local-firewall-policy.md](local-firewall-policy.md).

NAS-0051 adds hierarchical QoS scheduler endpoints:

```text
GET    /api/v1/system/qos-scheduler
POST   /api/v1/system/qos-scheduler/preview
POST   /api/v1/system/qos-scheduler/apply
POST   /api/v1/system/qos-scheduler/rollback
GET    /api/v1/system/qos-scheduler/history
GET    /api/v1/system/qos-scheduler/profiles
PUT    /api/v1/system/qos-scheduler/profiles/{name}
DELETE /api/v1/system/qos-scheduler/profiles/{name}
```

`GET /api/v1/system/qos-scheduler` returns the current hierarchical `tc`/IFB
plan, aggregate classes, per-session leaf classes, command fingerprint,
diagnostics, scheduler profile overrides, and recent evidence. Preview records
an event without changing kernel state. Apply executes the compiled command
plan, stores an active snapshot, and links the previous snapshot for rollback.
Rollback restores a selected snapshot, or the newest previous applied snapshot
when no snapshot is specified. Profile override endpoints manage hierarchy,
priority, aggregate caps, burst, committed burst, quantum, DSCP metadata, and
operator metadata for existing `bandwidth_profiles`.

Runtime QoS scheduler status is included in `/api/v1/system/status` under
`enforcement.qos_scheduler`, production readiness as
`hierarchical_qos_scheduler`, and support bundles as `api/qos-scheduler.json`
and `api/qos-scheduler-history.json`. See
[hierarchical-qos-scheduler.md](hierarchical-qos-scheduler.md).

NAS-0052 adds dual-stack shaping metadata and a vendor rate compiler:

```text
GET  /api/v1/system/rate-compiler
POST /api/v1/system/rate-compiler/compile
POST /api/v1/system/rate-compiler/decompile
```

`GET /api/v1/system/rate-compiler` returns compiler version, supported vendor
unit profiles, RFC references, evidence counters, and recent compile events.
`POST /api/v1/system/rate-compiler/compile` accepts normalized kbps intent and
returns vendor-safe RADIUS attributes for MikroTik, WISPr, UBNT, Huawei, H3C,
TPLink, ZTE, and shared kbps packs. The compiler records each preview in
`rate_compiler_events` and blocks values that exceed RADIUS integer bounds.
`POST /api/v1/system/rate-compiler/decompile` accepts observed vendor rate
attributes and normalizes them back into kbps intent for drift and support
evidence.

Rate compiler status is included in `/api/v1/system/status` under
`radius.rate_compiler`, production readiness as `vendor_rate_compiler`, and
support bundles as `api/rate-compiler.json`. The QoS scheduler summary now also
reports IPv4, IPv6, and IPv6-only shaped session counts. See
[dual-stack-rate-compiler.md](dual-stack-rate-compiler.md).

NAS-0053 adds dynamic VLAN bridge and subinterface lifecycle endpoints:

```text
GET  /api/v1/system/vlan-lifecycle
POST /api/v1/system/vlan-lifecycle/preview
POST /api/v1/system/vlan-lifecycle/apply
POST /api/v1/system/vlan-lifecycle/rollback
GET  /api/v1/system/vlan-lifecycle/history
```

`GET /api/v1/system/vlan-lifecycle` returns normalized VLAN intent, Linux
bridge and subinterface plans, hostapd VLAN file preview, command fingerprint,
diagnostics, active snapshot, and recent evidence. Preview records an event
without changing host state. Apply executes the owned `ip link` command plan,
writes the managed hostapd VLAN file atomically, stores an active snapshot, and
links the previous snapshot. Rollback restores a selected snapshot or the newest
previous restorable snapshot. History returns snapshot and event evidence.

Dynamic VLAN lifecycle status is included in `/api/v1/system/status` under
`enforcement.vlan_lifecycle`, production readiness as
`dynamic_vlan_lifecycle`, and support bundles as `api/vlan-lifecycle.json` and
`api/vlan-lifecycle-history.json`. See
[dynamic-vlan-lifecycle.md](dynamic-vlan-lifecycle.md).

NAS-0074 adds hostapd dynamic VLAN lifecycle endpoints:

```text
GET  /api/v1/system/hostapd-vlan-lifecycle
POST /api/v1/system/hostapd-vlan-lifecycle/preview
POST /api/v1/system/hostapd-vlan-lifecycle/apply
POST /api/v1/system/hostapd-vlan-lifecycle/rollback
GET  /api/v1/system/hostapd-vlan-lifecycle/history
```

`GET /api/v1/system/hostapd-vlan-lifecycle` returns the NAS-0074 report,
hostapd dynamic SSID bindings, `dynamic_vlan=1` fallback and
`dynamic_vlan=2` fail-closed counts, managed VLAN file preview, redacted
hostapd config preview, generated hostapd config fingerprint,
cleanup/rollback previews, release certification scope, and shared VLAN
lifecycle evidence. Preview records an event without changing host state.
Apply uses the existing VLAN lifecycle snapshot engine to
create managed bridges/subinterfaces, write the hostapd VLAN file atomically,
and attempt rollback on failure. Rollback restores a selected or previous
snapshot.

Hostapd dynamic VLAN lifecycle status is included in `/api/v1/system/status`
under `wireless.hostapd_vlan_lifecycle`, production readiness as
`hostapd_dynamic_vlan_lifecycle`, and support bundles as
`api/hostapd-vlan-lifecycle.json` and
`api/hostapd-vlan-lifecycle-history.json`. See
[hostapd-dynamic-vlan-lifecycle.md](hostapd-dynamic-vlan-lifecycle.md).

NAS-0075 adds 802.11r/k/v roaming and key lifecycle endpoints:

```text
GET  /api/v1/system/wireless-roaming-lifecycle
POST /api/v1/system/wireless-roaming-lifecycle/preview
POST /api/v1/system/wireless-roaming-lifecycle/apply
GET  /api/v1/system/wireless-roaming-lifecycle/history
```

`GET /api/v1/system/wireless-roaming-lifecycle` returns the effective roaming
profiles, active SSID bindings, neighbor AP inventory, FT key-reference state,
redacted hostapd preview, diagnostics, software completion state, and recent
evidence. Preview records an event without changing host files. Apply writes the
validated local hostapd roaming configuration and records durable evidence.

Roaming lifecycle status is included in `/api/v1/system/status` under
`wireless.roaming_lifecycle`, production readiness as
`wireless_roaming_lifecycle`, and support bundles as
`api/wireless-roaming-lifecycle.json` and
`api/wireless-roaming-lifecycle-history.json`. See
[80211rkv-roaming-key-lifecycle.md](80211rkv-roaming-key-lifecycle.md).

NAS-0076 adds Passpoint and Hotspot 2.0 lifecycle endpoints:

```text
GET  /api/v1/system/passpoint-lifecycle
POST /api/v1/system/passpoint-lifecycle/preview
POST /api/v1/system/passpoint-lifecycle/apply
GET  /api/v1/system/passpoint-lifecycle/history
```

`GET /api/v1/system/passpoint-lifecycle` returns the effective global and
per-SSID Passpoint profiles, ANQP/HS2.0 metadata counts, NAI realms, 3GPP
cellular networks, OSU provider state, redacted hostapd preview, diagnostics,
software completion state, and recent evidence. Preview records an event without
changing host files. Apply writes the validated local hostapd Passpoint and
Hotspot 2.0 configuration and records durable evidence.

Passpoint lifecycle status is included in `/api/v1/system/status` under
`wireless.passpoint_lifecycle`, production readiness as
`wireless_passpoint_lifecycle`, and support bundles as
`api/passpoint-lifecycle.json` and
`api/passpoint-lifecycle-history.json`. See
[passpoint-hotspot20-lifecycle.md](passpoint-hotspot20-lifecycle.md).

NAS-0077 adds DPSK and PPSK lifecycle endpoints:

```text
GET  /api/v1/system/ppsk-lifecycle
POST /api/v1/system/ppsk-lifecycle/preview
POST /api/v1/system/ppsk-lifecycle/apply
GET  /api/v1/system/ppsk-lifecycle/history
```

`GET /api/v1/system/ppsk-lifecycle` returns the effective global PPSK policy,
profile, group, credential, and per-SSID bindings, hostapd preview, redacted
`wpa_psk_file` preview, diagnostics, software completion state, and recent
evidence. Preview records an event without changing host files. Apply writes the
managed PPSK file and validated local hostapd configuration, then records
durable evidence.

PPSK lifecycle status is included in `/api/v1/system/status` under
`wireless.ppsk_lifecycle`, production readiness as `wireless_ppsk_lifecycle`,
and support bundles as `api/ppsk-lifecycle.json` and
`api/ppsk-lifecycle-history.json`. See
[dpsk-ppsk-lifecycle.md](dpsk-ppsk-lifecycle.md).

NAS-0078 adds controller estate lifecycle endpoints:

```text
GET  /api/v1/system/controller-estate-lifecycle
POST /api/v1/system/controller-estate-lifecycle/preview
POST /api/v1/system/controller-estate-lifecycle/apply
GET  /api/v1/system/controller-estate-lifecycle/history
```

`GET /api/v1/system/controller-estate-lifecycle` returns the selected
controller adapter, redacted configured state, inventory objects, WLAN
templates, object plans, compliance checks, desired-state hash, plan
fingerprint, software completion state, release certification scope, and recent
evidence. Preview records an event without contacting or mutating controllers.
Apply records an auditable lifecycle checkpoint and runtime status; destructive
controller deletes are not performed automatically.

Controller estate lifecycle status is included in `/api/v1/system/status` under
`integrations.controller.estate_lifecycle`, production readiness as
`controller_estate_lifecycle`, and support bundles as
`api/controller-estate-lifecycle.json` and
`api/controller-estate-lifecycle-history.json`. See
[controller-estate-lifecycle.md](controller-estate-lifecycle.md).

NAS-0079 adds RF/RRM/mesh/radio planning lifecycle endpoints:

```text
GET  /api/v1/system/rf-planning-lifecycle
POST /api/v1/system/rf-planning-lifecycle/preview
POST /api/v1/system/rf-planning-lifecycle/apply
GET  /api/v1/system/rf-planning-lifecycle/history
```

`GET /api/v1/system/rf-planning-lifecycle` returns the effective RF policy,
AP/radio topology, channel plan, power plan, mesh links, client-steering
policies, controller action previews, compliance checks, plan fingerprint,
software completion state, release certification scope, and recent evidence.
Preview records an event without changing radios or controllers. Apply records
an auditable lifecycle checkpoint and runtime status; physical AP/controller RF
mutation remains release certification until the adapter and firmware scope is
certified.

RF planning lifecycle status is included in `/api/v1/system/status` under
`wireless.rf_planning_lifecycle`, production readiness as
`rf_planning_lifecycle`, and support bundles as
`api/rf-planning-lifecycle.json` and
`api/rf-planning-lifecycle-history.json`. See
[rf-rrm-mesh-radio-planning.md](rf-rrm-mesh-radio-planning.md).

NAS-0080 adds rogue/WIPS/spectrum/location/multicast lifecycle endpoints:

```text
GET  /api/v1/system/wireless-security-lifecycle
POST /api/v1/system/wireless-security-lifecycle/preview
POST /api/v1/system/wireless-security-lifecycle/apply
GET  /api/v1/system/wireless-security-lifecycle/history
```

`GET /api/v1/system/wireless-security-lifecycle` returns wireless security
sensors, rogue classification and containment guardrails, WIPS detection
families, spectrum watch channels, location privacy zones, multicast policy
items, controller action previews, compliance checks, plan fingerprint, software
completion state, release certification scope, and recent evidence. Preview
records an event without containment or controller mutation. Apply records an
auditable checkpoint and runtime status; live containment, spectrum capture,
location accuracy, multicast airtime proof, and controller mutation remain
release certification until the exact hardware and firmware scope is certified.

Wireless security lifecycle status is included in `/api/v1/system/status` under
`wireless.security_lifecycle`, production readiness as
`wireless_security_lifecycle`, and support bundles as
`api/wireless-security-lifecycle.json` and
`api/wireless-security-lifecycle-history.json`. See
[wips-spectrum-location-multicast.md](wips-spectrum-location-multicast.md).

NAS-0081 adds controller CWA and safe per-session portal endpoints:

```text
GET  /api/v1/system/cwa-portal-lifecycle
POST /api/v1/system/cwa-portal-lifecycle/preview
POST /api/v1/system/cwa-portal-lifecycle/apply
GET  /api/v1/system/cwa-portal-lifecycle/history
```

`GET /api/v1/system/cwa-portal-lifecycle` returns RFC 8910 captive portal API
state, guest SSID redirect intent, walled-garden entries, controller CWA policy
previews, post-auth CoA actions, compliance checks, plan fingerprint, software
completion state, release certification scope, and recent evidence. Preview
records an event without controller mutation. Apply records an auditable
checkpoint and runtime status; live controller/AP redirect, DHCP/RA
advertisement, packet-capture proof, HA, scale, and soak remain release
certification for the exact hardware and firmware scope.

CWA lifecycle status is included in `/api/v1/system/status` under
`wireless.cwa_portal_lifecycle`, production readiness as
`cwa_portal_lifecycle`, and support bundles as `api/cwa-portal-lifecycle.json`
and `api/cwa-portal-lifecycle-history.json`. The portal service also serves the
RFC 8910 JSON endpoint at `/captive-portal/api` or `portal.cwa.captive_api_path`.
See [controller-cwa-safe-portal.md](controller-cwa-safe-portal.md).

Roles and policy rules may assign an enabled library entry with `acl_policy_name`. Validation rejects missing or disabled references, and deletion is blocked while a role or policy rule still uses the ACL. Portal policy evaluation and CoA persist the selected name on the active session. Local FreeRADIUS users receive the role's standard and configured vendor ACL attributes when the generated `users` file is applied.

After committing a role, user, ACL binding, or EAP framework policy through `/api/v1/apply`, run `POST /api/v1/system/radius-apply` (the **Apply RADIUS Config** action in Access Settings). This regenerates the local-user entries in `mods-config/files/authorize`, the legacy `users` path, and `mods-enabled/eap`, validates the complete FreeRADIUS configuration, and restarts FreeRADIUS. Database-backed portal decisions and CoA updates do not require this regeneration. Local bcrypt credentials support PAP and EAP-TTLS/PAP; CHAP and PEAP-MSCHAPv2 require a compatible cleartext or NT password verifier, while EAP-TLS uses certificates. NAS-0022 blocks enforce-mode generation when policy enables cataloged methods that this release cannot generate.

## Vendor Observability Endpoint

Runtime vendor compatibility evidence is available at:

```text
/api/v1/system/vendor-observability
/api/v1/system/vendor-observability/export?format=csv
/api/v1/system/vendor-observability/export?format=json
```

Example:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-observability | jq '.summary'
```

Use the catalog and reply preview endpoints to confirm what AegisNAS intends to support. Use vendor observability to confirm what the live RADIUS and dynamic-authorization paths are seeing: auth success and failure counts, parsed VSAs, VSA parse failures, unsupported attributes, CoA and disconnect outcomes, last event message, and the computed NAS compatibility score per vendor and NAS type.

The same summary is included in `/api/v1/system/status` under `radius.vendor_observability` and in `/api/v1/system/network-observability` under `vendor_observability`, so dashboards and support bundles can show static coverage next to runtime failures.

## Controller Adapter Catalog

Controller-native integration readiness is available at:

```text
/api/v1/system/controller-adapters
```

The response lists the supported controller adapters, whether each adapter is native or contract-based, the selected platform's capabilities, required site or network identifier, credential environment readiness, runtime sync status, and setup warnings. Cisco, Ruckus, and MikroTik readiness check `api_username_env` and `api_password_env`; token-based adapters check `api_token_env`. Aruba, FortiGate, and UniFi use `radius_profile` as an existing controller RADIUS profile; Ruckus uses it as the existing SmartZone authentication service name. Mist, MikroTik, Meraki, and OpenWiFi enterprise WLAN readiness requires `radius_server`, `radius_secret_env`, and the named secret in the process environment.

Controller policy operations are available at:

```text
GET  /api/v1/system/controller-sync/preview?operation=pull
GET  /api/v1/system/controller-sync/preview?operation=push
POST /api/v1/system/controller-sync
```

`pull` performs a read-only state request and compares observed controller resources with AegisNAS desired state. `push` requires `confirmation` to equal `PUSH CONTROLLER POLICY`. The Cisco native adapter reconciles ERS downloadable ACL and authorization profile resources with lookup-before-create/update behavior. The Aruba Central Classic native adapter reconciles enterprise WLAN resources through `/configuration/v2/wlan/{group}/{wlan}` and references a pre-existing Central RADIUS profile. The Juniper Mist native adapter pages through `/api/v1/sites/{site_id}/wlans` and creates or updates WPA2/WPA3 Enterprise WLANs by SSID. The Ruckus native adapter uses SmartZone v13_1 sessions and zone-scoped standard 802.1X WLAN resources. The FortiGate native adapter reconciles VDOM-scoped FortiAP VAP objects through the FortiOS CMDB API. The MikroTik native adapter reconciles managed RouterOS RADIUS and WiFi profile records without deleting or provisioning radios. The UniFi native adapter uses `/v1/sites/{siteId}/wifi/broadcasts`, resolves existing RADIUS and VLAN resources, and preserves unmanaged fields during full-object updates. The Meraki native adapter reads `/networks/{networkId}/wireless/ssids`, updates fixed slots only when their names exactly match configured SSIDs, and refreshes write-only RADIUS secrets on each confirmed push. The OpenWiFi native adapter pages OWGW AP inventory by venue or exact serial and queues preserved uCentral documents only for existing same-name enterprise SSIDs with valid interface VLAN placement. Successful OpenWiFi pushes expose safe `queued_commands` receipt entries containing only AP serial number, command UUID, and optional status. Manual operations update `controller_automation` runtime counters and durable integration history.

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/controller-sync/preview?operation=pull' | jq '.preview'

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"operation":"pull"}' \
  http://127.0.0.1:8083/api/v1/system/controller-sync | jq '.status, .result'
```

Configured `monitor` and `pull-config` modes use the read-only pull path in the background scheduler. Treat a vendor adapter as production-authoritative only after its endpoint contract, returned hashes, and policy enforcement have passed the hardware certification runbook.

## Support Bundle Endpoints

The appliance also serves support bundle preview and live bundle download at:

```text
/api/v1/system/support-bundle/summary
/api/v1/system/support-bundle
```

Use these when you want a redacted ZIP with runtime status, history, diagnostics, OpenAPI, and upgrade context in one operator bundle.

## Diagnostics Report Endpoints

The appliance also serves a cross-domain diagnostics snapshot at:

```text
/api/v1/system/diagnostics-report
```

And export variants at:

```text
/api/v1/system/diagnostics-report/export?format=json
/api/v1/system/diagnostics-report/export?format=csv
```

When scheduled diagnostics exports are enabled, the appliance also serves:

```text
/api/v1/system/diagnostics-exports
/api/v1/system/diagnostics-exports/download?name=<artifact>
```

When scheduled support bundle exports are enabled, the appliance also serves:

```text
/api/v1/system/support-bundle-exports
/api/v1/system/support-bundle-exports/download?name=<artifact>
```

When scheduled audit exports are enabled, the appliance also serves:

```text
/api/v1/system/audit-exports
/api/v1/system/audit-exports/download?name=<artifact>
```

When scheduled session exports are enabled, the appliance also serves:

```text
/api/v1/system/session-exports
/api/v1/system/session-exports/download?name=<artifact>
```

When scheduled session analytics exports are enabled, the appliance also serves:

```text
/api/v1/system/session-analytics-exports
/api/v1/system/session-analytics-exports/download?name=<artifact>
```

When scheduled voucher analytics exports are enabled, the appliance also serves:

```text
/api/v1/system/voucher-analytics-exports
/api/v1/system/voucher-analytics-exports/download?name=<artifact>
```

When scheduled voucher aging analytics exports are enabled, the appliance also serves:

```text
/api/v1/system/voucher-aging-analytics-exports
/api/v1/system/voucher-aging-analytics-exports/download?name=<artifact>
```

When scheduled voucher redemption analytics exports are enabled, the appliance also serves:

```text
/api/v1/system/voucher-redemption-analytics-exports
/api/v1/system/voucher-redemption-analytics-exports/download?name=<artifact>
```

When scheduled voucher expiry analytics exports are enabled, the appliance also serves:

```text
/api/v1/system/voucher-expiry-analytics-exports
/api/v1/system/voucher-expiry-analytics-exports/download?name=<artifact>
```

When scheduled integration exports are enabled, the appliance also serves:

```text
/api/v1/system/integration-exports
/api/v1/system/integration-exports/download?name=<artifact>
```

When scheduled HA exports are enabled, the appliance also serves:

```text
/api/v1/system/ha/exports
/api/v1/system/ha/exports/download?name=<artifact>
```

When scheduled network exports are enabled, the appliance also serves:

```text
/api/v1/system/network-exports
/api/v1/system/network-exports/download?name=<artifact>
```

When scheduled upstream AAA exports are enabled, the appliance also serves:

```text
/api/v1/system/upstream-aaa-exports
/api/v1/system/upstream-aaa-exports/download?name=<artifact>
```

When scheduled upgrade readiness exports are enabled, the appliance also serves:

```text
/api/v1/system/upgrade-readiness-exports
/api/v1/system/upgrade-readiness-exports/download?name=<artifact>
```

Use this report when you want one payload that combines:

- session and alert counts
- guest lifecycle and delivery state
- managed network apply and lease-trend stats
- HA role and failover counters
- upgrade-readiness results
- integration and runtime status snapshots
- controller, MDM sync, posture, and upstream AAA history counters

## Guest Lifecycle Endpoints

The appliance also serves a guest access lifecycle report at:

```text
/api/v1/system/guest-lifecycle
```

And export variants at:

```text
/api/v1/system/guest-lifecycle/export?format=json
/api/v1/system/guest-lifecycle/export?format=csv
/api/v1/system/guest-delivery-analytics
/api/v1/system/guest-delivery-analytics/export?format=json
/api/v1/system/guest-delivery-analytics/export?format=csv
/api/v1/system/guest-rejection-analytics
/api/v1/system/guest-rejection-analytics/export?format=json
/api/v1/system/guest-rejection-analytics/export?format=csv
/api/v1/system/guest-rejection-analytics-exports
/api/v1/system/guest-rejection-analytics-exports/download?name=<artifact>
/api/v1/system/guest-conversion-analytics
/api/v1/system/guest-conversion-analytics/export?format=json
/api/v1/system/guest-conversion-analytics/export?format=csv
/api/v1/system/guest-conversion-analytics-exports
/api/v1/system/guest-conversion-analytics-exports/download?name=<artifact>
/api/v1/system/guest-invite-analytics
/api/v1/system/guest-invite-analytics/export?format=json
/api/v1/system/guest-invite-analytics/export?format=csv
/api/v1/system/guest-invite-analytics-exports
/api/v1/system/guest-invite-analytics-exports/download?name=<artifact>
/api/v1/system/guest-delivery-failures
/api/v1/system/guest-delivery-failures/export?format=json
/api/v1/system/guest-delivery-failures/export?format=csv
/api/v1/system/guest-delivery-failures-exports
/api/v1/system/guest-delivery-failures-exports/download?name=<artifact>
/api/v1/system/guest-sponsor-analytics
/api/v1/system/guest-sponsor-analytics/export?format=json
/api/v1/system/guest-sponsor-analytics/export?format=csv
/api/v1/system/guest-delivery-analytics-exports
/api/v1/system/guest-delivery-analytics-exports/download?name=<artifact>
/api/v1/system/guest-sponsor-analytics-exports
/api/v1/system/guest-sponsor-analytics-exports/download?name=<artifact>
/api/v1/system/guest-lifecycle-exports
/api/v1/system/guest-lifecycle-exports/download?name=<artifact>
```

Use the delivery analytics endpoints when you want the sponsor-approval backlog, approval and invite delivery failure mix, top sponsors, and approval-to-completion timing without exporting the full registration history.

Use the rejection analytics endpoints when you want the top rejection reasons, sponsor versus non-sponsor rejection mix, after-approval reversals, and submit-to-rejection timing without scanning the raw request table by hand. Enable the scheduled rejection export path when you want recurring snapshots in `Backups` without depending on a live guest analytics pull.

Use the guest conversion analytics endpoints when you want funnel reach, submit-to-approval / invite / completion timing, and the main drop-off points between approval, invite delivery, and successful completion.

Use the invite analytics endpoints when you want queued, sent, and failed invite throughput, approval-to-invite timing, and completion-after-invite movement without paging through the raw guest request table.

Use the scheduled invite analytics export endpoints when you want that invite-throughput and completion view written to disk on a timer for operator handoff or post-incident review.

Use the delivery failure endpoints when you want top approval or invite error reasons, queued-invite age, and sponsor or company hotspots without paging through the raw registration table.

Use the scheduled delivery failure export endpoints when you want those hotspots saved to disk on a timer for later review or incident handoff.

Use the sponsor analytics endpoints when you want aging sponsor backlog, slow-response hotspots, sponsor-by-sponsor pending queues, and approval timing without leaving the guest operations workflow.

Optional query parameters:

- `status=pending|approved|rejected|completed`
- `limit=<n>`
- `window_hours=<n>`
- `bucket_count=<n>`

Use this report when you want:

- pending, approved, rejected, and completed guest-request counts in one place
- approval and invite delivery failure visibility without scanning raw rows by hand
- recent submitted/approved/rejected/completed trends for the guest workflow window
- handoff-ready JSON or CSV exports from the same guest workflow page operators already use
- recurring JSON or CSV artifacts that land on disk without waiting for a manual export click

From the admin UI:

1. sign in
2. open `Guest Requests`
3. filter by status when you want a narrower lifecycle view
4. review the summary and recent lifecycle trend
5. export `JSON` or `CSV` when you need an operator handoff artifact

## Session History Endpoints

The appliance also keeps durable session and accounting history at:

```text
/api/v1/system/session-history
```

And export variants at:

```text
/api/v1/system/session-history/export?format=json
/api/v1/system/session-history/export?format=csv
```

Optional query parameters:

- `username=<exact-username>`
- `auth_method=<exact-method>`
- `active=true|false`
- `limit=<n>`

Use this history when you want:

- a durable view of who authenticated, how, and when the session ended
- accounting-oriented byte and duration exports for operator handoff
- recurring session artifacts without relying on a manual export step

For summarized session activity trends, the appliance also serves:

```text
/api/v1/system/session-analytics
/api/v1/system/session-analytics/export?format=json
/api/v1/system/session-analytics/export?format=csv
```

Optional query parameters:

- `username=<exact-username>`
- `auth_method=<exact-method>`
- `window_hours=<n>`
- `bucket_count=<n>`

Use this analytics view when you want:

- started vs ended session trends over the selected window
- peak concurrent session counts without scanning raw rows by hand
- auth-method, role, and VLAN mix snapshots for operator review
- ended-session traffic and duration summaries that are safer to reason about than cumulative active-session bytes

## Voucher Analytics Endpoints

The appliance also serves voucher inventory and usage analytics at:

```text
/api/v1/system/voucher-analytics
/api/v1/system/voucher-analytics/export?format=json
/api/v1/system/voucher-analytics/export?format=csv
/api/v1/system/voucher-aging-analytics
/api/v1/system/voucher-aging-analytics/export?format=json
/api/v1/system/voucher-aging-analytics/export?format=csv
/api/v1/system/voucher-redemption-analytics
/api/v1/system/voucher-redemption-analytics/export?format=json
/api/v1/system/voucher-redemption-analytics/export?format=csv
/api/v1/system/voucher-expiry-analytics
/api/v1/system/voucher-expiry-analytics/export?format=json
/api/v1/system/voucher-expiry-analytics/export?format=csv
/api/v1/system/voucher-expiry-analytics-exports
/api/v1/system/voucher-expiry-analytics-exports/download?name=<artifact>
/api/v1/system/voucher-analytics-exports
/api/v1/system/voucher-analytics-exports/download?name=<artifact>
/api/v1/system/voucher-aging-analytics-exports
/api/v1/system/voucher-aging-analytics-exports/download?name=<artifact>
```

Optional query parameters:

- `window_hours=<n>`
- `bucket_count=<n>`

Use this analytics view when you want:

- active, exhausted, expired, and unused voucher counts in one place
- remaining-use and utilization snapshots without scanning raw codes by hand
- role mix and voucher-state mix for operator review
- bucketed voucher creation and expiry pressure trends from the same page where operators create vouchers
- recurring JSON or CSV voucher analytics artifacts without waiting for a manual export click

Use the voucher redemption analytics endpoints when you want:

- a clear view of how many current vouchers were actually redeemed
- first-use delay from voucher creation to real session start
- repeat-use versus one-time-use behavior across the current voucher set
- bucketed voucher session starts, first redemptions, and completed-session traffic without pivoting over raw accounting rows

Use the voucher expiry analytics endpoints when you want:

- a forward-looking view of vouchers expiring inside the selected horizon
- unused vouchers that are about to expire without ever being redeemed
- remaining finite-use capacity that will age out with upcoming expirations
- role hotspots for expiring inventory and unused at-risk vouchers
- bucketed upcoming expiry pressure instead of only historical voucher creation counts

From the admin UI:

1. sign in
2. open `Vouchers`
3. review the inventory summary, role mix, and state mix
4. review the expiry horizon when you need upcoming expiration pressure and unused-at-risk visibility
5. review the redemption summary and trend when you need first-use and reuse behavior
6. export `JSON` or `CSV` when you need a handoff-ready snapshot
7. review scheduled voucher analytics export runtime and artifacts when recurring export is enabled

From the admin UI:

1. sign in
2. open `Sessions` for live activity and trend analytics
3. open `Backups` for durable `Session History`
4. export `JSON` or `CSV`
5. review scheduled session export runtime and artifacts when recurring export is enabled
6. review scheduled session analytics export runtime and artifacts when recurring analytics capture is enabled

## Upstream AAA History Endpoints

The appliance also keeps durable upstream AAA probe history at:

```text
/api/v1/system/upstream-aaa-history
```

And export variants at:

```text
/api/v1/system/upstream-aaa-history/export?format=json
/api/v1/system/upstream-aaa-history/export?format=csv
```

Optional query parameters:

- `server=<home-server-name>`
- `status=ok|degraded|down|disabled`
- `limit=<n>`

Use this history when you want:

- a durable timeline for upstream RADIUS probe health
- exportable evidence for fail-over, reject, and timeout investigation
- a way to compare live dashboard state with recent probe outcomes

From the admin UI:

1. sign in
2. open `Backups`
3. review `Upstream AAA History`
4. export `JSON` or `CSV` when you need a handoff-ready timeline
5. review scheduled upstream AAA export runtime and artifacts when recurring export is enabled

From the admin UI:

1. sign in
2. open `Backups`
3. select `Refresh Report`
4. download `JSON` or `CSV`
5. review the scheduled export runtime and recent artifacts when recurring export is enabled

## Upgrade Readiness Export Endpoints

The appliance also serves live upgrade readiness at:

```text
/api/v1/system/upgrade-readiness
```

When recurring upgrade readiness export is enabled, operators can also use:

```text
/api/v1/system/upgrade-readiness-exports
/api/v1/system/upgrade-readiness-exports/download?name=<artifact>
```

Use these when you want:

- durable migration-rehearsal evidence for a maintenance window
- a saved trail of config validation and schema checks
- recurring readiness snapshots without manually rerunning the report

From the admin UI:

1. sign in
2. open `Backups`
3. review `Upgrade Readiness`
4. review the scheduled upgrade readiness export runtime and artifacts when recurring export is enabled

## Integration History Endpoints

The appliance also keeps durable automation history for controller sync, MDM sync, and posture evaluation at:

```text
/api/v1/system/integration-history
```

And export variants at:

```text
/api/v1/system/integration-history/export?format=json
/api/v1/system/integration-history/export?format=csv
```

Optional query parameters:

- `component=controller_automation`
- `component=mdm_sync`
- `component=posture_checks`
- `limit=<n>`

Use this history when you want:

- more than the last runtime status message
- a quick operator timeline for sync failures and recoveries
- exportable evidence for controller or MDM troubleshooting
- recurring integration artifacts without relying on manual export timing

Controller history details can include adapter name, request URL, desired-state hash, observed-state hash, drift flag and count, applied and failed item counts, controller health, compatibility score, and response warnings. These fields also flow into network observability so operators can see whether a controller accepted the latest AegisNAS policy or reported drift.

From the admin UI:

1. sign in
2. open `Backups`
3. review `Integration History`
4. export `JSON` or `CSV` when you need to hand it to another team
5. review scheduled integration export runtime and artifacts when recurring export is enabled

## HA History Endpoints

The appliance also keeps durable HA history at:

```text
/api/v1/system/ha/history
```

And export variants at:

```text
/api/v1/system/ha/history/export?format=json
/api/v1/system/ha/history/export?format=csv
```

When recurring HA export is enabled, operators can also use:

```text
/api/v1/system/ha/exports
/api/v1/system/ha/exports/download?name=<artifact>
```

Use this history when you want:

- a failover and replication timeline beyond the latest runtime message
- exportable evidence for HA drills and incident review
- recurring HA artifacts without relying on manual export timing

From the admin UI:

1. sign in
2. open `Backups`
3. review `HA History`
4. export `JSON` or `CSV`
5. review scheduled HA export runtime and artifacts when recurring export is enabled

## Network History Endpoints

The appliance also keeps durable managed network and DHCP lease history at:

```text
/api/v1/system/network-apply-history
/api/v1/system/dhcp-lease-history
```

And export variants at:

```text
/api/v1/system/network-apply-history/export?format=json
/api/v1/system/network-apply-history/export?format=csv
/api/v1/system/dhcp-lease-history/export?format=json
/api/v1/system/dhcp-lease-history/export?format=csv
```

When recurring network export is enabled, operators can also use:

```text
/api/v1/system/network-exports
/api/v1/system/network-exports/download?name=<artifact>
```

Use this history when you want:

- a durable apply and rollback timeline beyond the latest validation toast
- recurring DHCP lease evidence for client troubleshooting
- exportable network change artifacts without relying on a manual export step

When passive profiling is enabled, DHCP observations also update device inventory with hostname, DHCP client ID, MAC OUI, profile risk score, and risk reasons. If posture remediation is enabled, high-risk active sessions can be marked with `quarantine-profile-risk`.

Operators and trusted collectors can also submit richer profile observations at:

```text
/api/v1/devices/profile-observations
```

The request can include MAC, IP, username, session ID, user-agent, hostname, DHCP fingerprint, LLDP chassis or port, and CDP device or port fields. AegisNAS stores those signals on the device inventory record, updates profile risk reasons, and can quarantine high-risk active sessions when posture remediation is enabled.

Device certificate lifecycle operations are available at:

```text
/api/v1/devices/certificates
/api/v1/devices/certificates/{id}/status
/api/v1/devices/certificates/{id}/revoke
/api/v1/devices/certificates/{id}/renew
/api/v1/devices/certificates/crl
```

Use these to inspect active, expired, and revoked certificates, revoke lost-device certificates, renew a device certificate, and download an internal-CA CRL. Revoke and renew require an ops or super admin session.

Enterprise certificate lifecycle policy and enrollment-request evaluation are available at:

```text
/api/v1/system/certificate-lifecycle
/api/v1/system/certificate-lifecycle/evaluate
```

Use these to review the effective EST/SCEP/BYOD template and issuer policy, issuer rotation state, CRL/OCSP readiness, hashed lifecycle event history, and current certificate inventory. The evaluation endpoint accepts protocol, template, issuer, device binding, CSR PEM, renewal, revocation, CRL/OCSP, and optional audit evidence. Audit records store hashes for subjects, SANs, serials, and device IDs rather than raw identity material.

Password lifecycle and supplicant profile delivery operations are available at:

```text
/api/v1/system/supplicant-lifecycle
/api/v1/system/supplicant-lifecycle/evaluate
/api/v1/system/supplicant-lifecycle/profile
```

Use these to review platform, EAP, verifier, password-change, trust-anchor, RADIUS server-name, TLS delivery, and profile-signing policy. The profile endpoint renders a signed package containing the manifest, platform-specific payload, content hash, signature, and signing-key fingerprint. Audit records store hashed usernames and device IDs, not passwords or profile contents.

From the admin UI:

1. sign in
2. open `Access Settings` to review live network history
3. open `Backups`
4. review scheduled network export runtime and artifacts when recurring export is enabled

## Audit History Endpoints

The appliance also serves a durable audit timeline at:

```text
/api/v1/system/audit-history
```

And export variants at:

```text
/api/v1/system/audit-history/export?format=json
/api/v1/system/audit-history/export?format=csv
```

Optional query parameters:

- `user=<admin-subject>`
- `action_prefix=download_`
- `action_prefix=guest_`
- `limit=<n>`

Use this history when you want:

- a quick record of admin-visible actions
- change-window evidence for network, HA, or upgrade work
- an exportable operator timeline for incident review
- recurring audit artifacts without relying on a manual export step

From the admin UI:

1. sign in
2. open `Backups`
3. review `Audit History`
4. export `JSON` or `CSV` when you need a handoff-ready timeline
5. review scheduled audit export runtime and artifacts when recurring export is enabled

## What The Schema Includes

The OpenAPI document includes:

- public auth and documentation endpoints
- authenticated admin endpoints
- bearer-auth security scheme
- grouped tags for system, network, HA, upgrade, guest, and AAA paths
- AegisNAS-specific role hints through `x-aegisnas-roles`
- visibility hints through `x-aegisnas-visibility`

That means integrations can see both:

- the path and method shape
- the likely operator role needed to call it

## Authentication Expectations

Most admin endpoints require:

```text
Authorization: Bearer <token>
```

The schema advertises this as `bearerAuth`.

The common flow is:

1. use `GET /api/v1/auth/options`
2. sign in through token or admin SSO
3. call the protected endpoint with the bearer token

When `admin_webauthn.mode: enforce` and the authenticated role requires
passkey step-up, token login starts with `POST /api/v1/auth/token/start`.
OIDC and SAML callbacks redirect to the login page with a pending
`webauthn_state`. The browser must complete
`POST /api/v1/auth/webauthn/login/finish` before protected admin APIs accept
the session token.

## Role Hints

The OpenAPI document includes `x-aegisnas-roles` for authenticated operations.

Common values are:

- `read_only`
- `guest_admin`
- `ops_admin`
- `super_admin`

Treat these as operational hints that match the current appliance authorization model.

## Good Uses For The Schema

Use the OpenAPI JSON for:

- internal tooling
- support automation
- API client generation experiments
- runbook authoring
- change-review prep before automation is pointed at the appliance
- mapping diagnostics-report exports into external support workflows
- mapping integration-history exports into controller and endpoint support workflows
- mapping scheduled integration exports into controller, MDM, and posture support handoffs
- mapping scheduled audit exports into change-review and incident timelines
- mapping scheduled HA exports into failover drill evidence and recovery handoffs
- mapping scheduled upstream AAA exports into RADIUS fail-over and timeout investigations
- mapping scheduled session analytics exports into recurring access-pattern and concurrency reviews
- mapping vendor-compatibility reports into packet simulation, support, and controller-pack planning

## Operational Reminder

The OpenAPI schema describes the live contract, but it does not replace change safety.

For risky actions like:

- network apply
- rollback restore
- HA activation

use the matching runbook as well so you keep the preview, validation, backup, and rollback steps in place.

## Vendor Identity API

`GET /api/v1/system/vendor-identity` returns the current PEN lifecycle, verified evidence, bounded legacy decode state, migration history, recovery warnings, and counters. `POST /api/v1/system/vendor-identity/migrations/preview`, `POST /api/v1/system/vendor-identity/migrations/apply`, and `POST /api/v1/system/vendor-identity/migrations/{id}/rollback` are `super_admin` operations. Preview verifies the fixed IANA registry and returns a one-time 15-minute confirmation token. See `vendor-identity.md` for schemas and failure behavior.

## Attribute Registry API

`GET /api/v1/system/dictionary-release-profiles` returns the pinned dictionary release profiles, vendor aliases, attribute aliases, firmware scopes, and active/default profile IDs. Optional `id` filters one profile.

`GET /api/v1/system/compatibility-evidence` returns software evidence states with cursor pagination. Filters: `pack`, `vendor`, `semantic`, `software_state`, `certification_state`, `claim`, `search`, `limit`, and `cursor`. See [compatibility-evidence.md](compatibility-evidence.md).

`GET /api/v1/system/vsa-codec` returns VSA codec software readiness, supported vendor type/length formats, grouped/OID counts, repeated value support, packet limits, and source hash provenance. See [vsa-codec.md](vsa-codec.md).

`GET /api/v1/system/attribute-registry` returns the generated typed registry with release/hash provenance and cursor pagination. Filters: `release`, `vendor`, `pen`, `pack`, `semantic`, `status`, `search`, `limit`, and `cursor`. See [attribute-registry.md](attribute-registry.md) and [dictionary-release-profiles.md](dictionary-release-profiles.md).
