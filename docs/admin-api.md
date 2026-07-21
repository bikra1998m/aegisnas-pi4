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

The report checks config validation, declared hardware scaling, AegisNAS vendor identity and placeholder PEN use, dictionary release profile integrity, product dictionary detection, active vendor compatibility packs, deployed NAS profile coverage, active feature gates, controller readiness, and vendor runtime evidence from live RADIUS/CoA counters. A short summary also appears in `/api/v1/system/status` as `production_readiness`.

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
/api/v1/system/policy-sets/versions/{fromID}/compare/{toID}
```

Use these endpoints to create immutable policy-set versions, submit them for
maker-checker approval, activate approved versions, compare flattened rule
changes, simulate draft decisions, and roll back to prior approved versions.
The same state appears in `/api/v1/system/status` under `radius.policy_sets`,
inside `/api/v1/system/policy-engine` as `policy_sets`, in production readiness
as `policy_set_governance`, and in support bundles as `api/policy-sets.json`.
See [versioned-policy-sets.md](versioned-policy-sets.md).

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

Each policy stores a stable name, optional vendor inbound/outbound ACL names, and up to 64 normalized rules. ACL policy changes are included in config revision snapshots and rollback. A vendor reply preview containing only `acl_policy_name` loads an enabled applied policy and reports `acl_policy_loaded: true`; explicit `acl_rules` remain available for one-off previews.

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
