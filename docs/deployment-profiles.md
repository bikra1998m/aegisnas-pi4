# Deployment Profiles

This guide explains how to tune AegisNAS for different hardware classes and deployment forms without maintaining separate forks of the product.

The current implementation adds a profile-aware control plane through:

- `deployment.profile`
- `deployment.form`
- `deployment.hardware.*`
- `telemetry.enabled`
- `ailite.enabled`
- `ailite.mode`
- `policy.runtime_shaping_enabled`

Use this guide together with:

- [Hardware Sizing And Deployment Matrix](hardware-sizing-and-deployment-matrix.md)
- [Feature Capability Framework](feature-capability-framework.md)
- [Ubuntu Appliance Deployment](ubuntu-appliance-deployment.md)
- [Wireless Access And UI Guide](wireless-access-ui-guide.md)

## Profiles

### `lite`

Use this for constrained hardware and very small sites.

Recommended direction:

- disable AI Lite
- keep `ailite.mode: lite` when AI is off
- disable telemetry
- disable runtime shaping
- reduce `radius.max_sessions`
- prefer external APs on VM builds
- only turn on local wireless in VMs when `deployment.hardware.wireless_passthrough: true`
- consider `radius.upstream.status_check: none`
- keep `portal.guest_workflows.self_registration_enabled: false`
- keep `portal.guest_workflows.sponsor_approval_enabled: false`
- keep `onboarding.device_inventory_enabled: false`
- keep `onboarding.portal_enabled: false`
- keep `onboarding.certificate_enrollment_enabled: false`
- keep `onboarding.eap_tls_enabled: false`
- keep `profiling.passive_enabled: false`
- keep `profiling.posture_enabled: false`
- keep `profiling.mdm_sync_enabled: false`
- keep `integrations.admin_sso.enabled: false`
- keep `integrations.controller.enabled: false`
- keep `governance.delegated_admin_enabled: false`
- keep `governance.multi_tenant_enabled: false`

### `branch`

This is the balanced default profile.

Recommended direction:

- AI Lite on
- `ailite.mode: lite`
- telemetry on
- runtime shaping on when needed
- keep full AI blocked until `ailite.endpoint` and `ailite.model` are configured
- normal upstream AAA probing
- guest self-registration is acceptable for pilot production once `portal.local_fallback`, branding, and delivery settings are in place
- sponsor approval is acceptable when email or SMS transport is configured and tested
- device inventory is acceptable for pilot production
- onboarding portal is acceptable once portal, identity, and CA mode dependencies are in place
- passive profiling is acceptable when MAC inventory is enabled and poll intervals stay conservative
- keep certificate enrollment and posture decisions behind enterprise gating unless the deployment is truly ready
- SIEM export is a normal branch feature once batching and secrets are tested
- controller automation is acceptable for external AP estates, but it should follow the external AP deployment model
- admin SSO and delegated admin are acceptable for smaller teams when identity dependencies are in place
- keep MDM sync and multi-tenant governance behind enterprise gating
- suitable for most pilot and branch appliance builds

### `enterprise`

Use this when you have more hardware headroom and heavier auth or policy load.

Recommended direction:

- keep guest self-registration and sponsor approval on this tier when guest access is a customer-facing workflow
- configure SMTP or SMS delivery before enabling invites or sponsor approval
- treat this as the preferred tier for branded guest onboarding and approval-heavy guest programs
- full AI mode on when a provider endpoint and model are configured
- telemetry on
- runtime shaping on
- larger `radius.max_sessions`
- active upstream AAA probing
- make this the default target for certificate enrollment and EAP-TLS onboarding
- use posture checks only after MDM or compliance sources are configured and tested
- treat passive profiling and remediation as normal production features on this tier
- make this the default target for authoritative MDM/UEM sync, admin SSO, delegated admin, and multi-tenant governance
- use controller automation here when the appliance is part of a larger controller-managed Wi-Fi estate
- treat SIEM export as part of the normal production baseline

### `custom`

Use this when the operator wants to control each feature manually.

It keeps the profile metadata and warnings, but avoids pushing a strong opinion over the rest of the config.

## Deployment Forms

### `physical`

Use this for:

- Raspberry Pi class appliances
- mini-PC edge appliances
- x86 branch or enterprise boxes
- hardware with local Wi-Fi radios

### `virtual`

Use this for:

- VMware
- Hyper-V
- Proxmox
- KVM

The virtual form assumes external APs are usually the safer model. If local wireless is enabled in a VM, the dashboard warns about that choice because a plain virtual NIC is not a real radio.

## How To Use It In The UI

1. Open `Access Settings`
2. choose the profile
3. choose `Physical Appliance` or `Virtual Appliance`
4. enter memory, CPU, and storage hints for the target box
5. click `Apply Profile Defaults`
6. review the feature toggles and save

The profile action updates real config fields such as:

- `ailite.enabled`
- `ailite.mode`
- `telemetry.enabled`
- `policy.runtime_shaping_enabled`
- `radius.max_sessions`
- `radius.interim_update_seconds`
- `radius.upstream.status_check`
- `portal.guest_workflows.*`
- `onboarding.*`
- `profiling.*`
- `integrations.*`
- `governance.*`

Notable production-facing runtime that now sits behind those fields includes:

- guest self-registration and sponsor approval
- onboarding portal and device inventory
- internal or external CA certificate enrollment
- token-backed MDM sync and compliance webhook posture checks
- admin SSO through OIDC or SAML
- SIEM export and controller automation
- delegated admin and tenant-aware governance

## Automatic Hardware Scaling

AegisNAS now derives a scaling plan from `deployment.hardware.memory_mb`, `deployment.hardware.cpu_cores`, and `deployment.hardware.storage_gb`.

The plan appears in `/api/v1/system/status`, `/api/v1/system/settings/evaluate`, the dashboard, and the Access Settings preview as `deployment.scaling`.

Scaling modes:

| Mode | Selection rule | Operational behavior |
| --- | --- | --- |
| `lite` | below branch floor, or unknown CPU/RAM | keeps retention short and gates heavyweight automation |
| `branch` | 2 CPU cores, 4096 MB RAM, and unknown or at least 32 GB storage | allows normal branch automation and moderate history |
| `enterprise` | 4 CPU cores, 8192 MB RAM, and unknown or at least 64 GB storage | allows enterprise-only posture, HA, tenant, and certificate workflows when dependencies are configured |

When the selected profile is above the hardware scaling mode, AegisNAS keeps the selected profile visible but returns warnings and capability gates for features that should not run on that hardware. Declare storage for production boxes so retention guidance is based on real disk headroom. This lets one image run from low-spec lab devices up to larger enterprise appliances without pretending every target can safely run every feature.

## How To Use It In YAML

Example low-power edge appliance:

```yaml
deployment:
  profile: lite
  form: physical
  hardware:
    memory_mb: 1024
    cpu_cores: 4
    storage_gb: 8
    prefer_external_ap: true

telemetry:
  enabled: false

ailite:
  enabled: false
  mode: lite
  recommendation_limit: 25

policy:
  runtime_shaping_enabled: false
```

Example virtual appliance:

```yaml
deployment:
  profile: branch
  form: virtual
  hardware:
    memory_mb: 8192
    cpu_cores: 4
    storage_gb: 32
    prefer_external_ap: true

wireless:
  enabled: false
```

Example enterprise onboarding target:

```yaml
deployment:
  profile: enterprise
  form: physical
  hardware:
    memory_mb: 16384
    cpu_cores: 8
    storage_gb: 64

portal:
  enabled: true
  local_fallback: true

radius:
  eap:
    default_type: tls
    check_crl: true
    check_all_crl: true
    ca_path_reload_interval: 3600
    ocsp:
      enabled: false
      use_nonce: true
      timeout_seconds: 5
      soft_fail: false

onboarding:
  device_inventory_enabled: true
  portal_enabled: true
  certificate_enrollment_enabled: true
  eap_tls_enabled: true
  ca_mode: internal
  ca_cert_path: /etc/aegisnas/pki/ca.crt
  ca_key_path: /etc/aegisnas/pki/ca.key

profiling:
  mac_inventory_enabled: true
  passive_enabled: true
  posture_enabled: true
  mdm_sync_enabled: true
  mdm_provider: workspace-one-like
  mdm_endpoint: https://mdm.example.com/api

integrations:
  admin_sso:
    enabled: true
    provider: oidc
    issuer_url: https://idp.example.com/.well-known/openid-configuration
    client_id: aegisnas-admin
    client_secret_env: AEGIS_ADMIN_SSO_CLIENT_SECRET
    redirect_url: https://admin.example.com/auth/callback
    groups_claim: groups
  siem:
    enabled: true
    provider: webhook
    endpoint: https://siem.example.com/collect
    api_key_env: AEGIS_SIEM_API_KEY
  controller:
    enabled: true
    platform: aruba
    endpoint: https://apigw-prod2.central.arubanetworks.com
    api_token_env: AEGIS_CONTROLLER_API_TOKEN
    radius_profile: aegisnas-radius
    sync_mode: monitor
    site: branch-west

governance:
  delegated_admin_enabled: true
  rbac_mode: hybrid
  external_groups_enabled: true
  multi_tenant_enabled: true
  tenant_claim: tenant
```

Controller automation supports the generic REST contract plus Cisco, Aruba, Juniper Mist, Ruckus, Fortinet, MikroTik, and UniFi adapters. Each sync includes adapter capability metadata and a desired-state hash so controller responses can report drift, applied counts, failed counts, health, compatibility score, and observed-state hash into integration history and network observability. Operators can check `/api/v1/system/controller-adapters` or the dashboard before enabling automation to confirm the selected adapter, token environment, site or network identifier, native push support, drift detection, dynamic ACL support, and CoA readiness.

Cisco ISE uses the native ERS API rather than the generic contract. Configure the ISE base URL plus Basic-auth credential environment names:

```yaml
integrations:
  controller:
    enabled: true
    platform: cisco
    endpoint: https://ise-pan.example.com:9060
    api_username_env: AEGIS_CISCO_ISE_USERNAME
    api_password_env: AEGIS_CISCO_ISE_PASSWORD
    sync_mode: monitor
    site: branch-west
```

Pull mode reads `/ers/config/downloadableacl` and `/ers/config/authorizationprofile`, compares each managed object with the desired ACL and role state, and reports object-level drift. Confirmed push mode performs filtered lookup followed by create or update, carries an ERS CSRF token when the server supplies one, and never deletes controller objects.

The Aruba adapter targets the Classic Aruba Central Configuration API. Set `site` to the Central group and `radius_profile` to an existing Central RADIUS server profile. For each configured `wpa2-enterprise` or `wpa3-enterprise` SSID, pull mode reads `/configuration/v2/wlan/{group}/{wlan}` and reports field-level drift; confirmed push mode creates missing WLANs with POST and updates changed WLANs with PUT. Requests use the bearer token named by `api_token_env`, retry one `429` response using `Retry-After`, and never delete WLANs. Open, personal, and captive-portal SSIDs are reported as unsupported warnings. This adapter does not yet mutate Central RADIUS profiles, guest portals, roles, ACLs, or CoA resources.

Juniper Mist uses the site WLAN API and Token authentication. Configure the regional API host, Mist site UUID, RADIUS server, and a RADIUS shared-secret environment variable:

```yaml
integrations:
  controller:
    enabled: true
    platform: juniper-mist
    endpoint: https://api.mist.com
    api_token_env: AEGIS_MIST_API_TOKEN
    radius_server: 192.0.2.10
    radius_secret_env: AEGIS_MIST_RADIUS_SECRET
    sync_mode: monitor
    site: 000000ab-00ab-00ab-00ab-0000000000ab
```

Pull mode pages through `/api/v1/sites/{site_id}/wlans` and compares WLANs by SSID. Confirmed push updates an existing WLAN by generated ID or creates a missing site WLAN. Managed fields cover WPA2/WPA3 Enterprise security, RADIUS authentication and accounting, optional CoA, static or standard dynamic VLANs, SSID visibility, isolation, and client limits. Secrets are read only at execution time and previews use `redacted`. Personal, open, captive-portal, bandwidth, and identity-source policy remain outside this native slice and produce warnings rather than speculative API writes.

Ruckus SmartZone uses Public API v13_1 with controller session authentication. Set `site` to the Ruckus zone ID, `radius_profile` to an existing zone authentication service name, and provide controller credentials through environment variables:

```yaml
integrations:
  controller:
    enabled: true
    platform: ruckus
    endpoint: https://smartzone.example.com
    api_username_env: AEGIS_RUCKUS_USERNAME
    api_password_env: AEGIS_RUCKUS_PASSWORD
    radius_profile: aegisnas-radius
    sync_mode: monitor
    site: 21a18b1c-e260-48c8-866c-69e66c81368e
```

Each operation logs in through `/wsg/api/public/v13_1/session`, pages through the zone WLAN inventory, reads full WLAN details, and logs out. Confirmed push creates missing `standard8021X` WLANs and applies changed fields with PATCH, never PUT or DELETE. The native fields cover WPA2/WPA3 Enterprise encryption, authentication-service reference, local breakout, static or AAA-overridden VLAN, SSID visibility, client isolation, and per-radio client limits. Guest, portal, bandwidth, identity-source, accounting-profile, ACL, and CoA automation are outside this slice.

FortiGate uses the FortiOS CMDB API with a scoped REST API administrator token. Set `site` to the VDOM and `radius_profile` to an existing FortiGate RADIUS profile:

```yaml
integrations:
  controller:
    enabled: true
    platform: fortinet
    endpoint: https://fortigate.example.com
    api_token_env: AEGIS_FORTIGATE_API_TOKEN
    radius_profile: aegisnas-radius
    sync_mode: monitor
    site: root
```

Pull mode reads each managed object from `/api/v2/cmdb/wireless-controller/vap/{name}?vdom={vdom}`. Confirmed push creates missing VAPs through the collection and updates existing VAPs by name. Managed fields cover WPA2/WPA3 Enterprise security, RADIUS profile selection, static and dynamic VLAN settings, broadcast visibility, intra-VAP isolation, and client limits. The adapter never deletes VAPs and does not mutate firewall policy, NAC profiles, captive portals, RADIUS server objects, or FortiGate user groups.

MikroTik uses the RouterOS v7 REST API with Basic authentication. Configure a dedicated least-privilege RouterOS account, a managed-site label, and the RADIUS endpoint and secret environment variable:

```yaml
integrations:
  controller:
    enabled: true
    platform: mikrotik
    endpoint: https://router.example.com
    api_username_env: AEGIS_MIKROTIK_USERNAME
    api_password_env: AEGIS_MIKROTIK_PASSWORD
    radius_server: 192.0.2.10
    radius_secret_env: AEGIS_MIKROTIK_RADIUS_SECRET
    sync_mode: monitor
    site: branch-west
```

Pull mode lists `/rest/radius` and the RouterOS 7.13+ `/rest/interface/wifi/security`, `/datapath`, and `/configuration` collections. Confirmed push creates missing AegisNAS-managed records with PUT and updates changed records by `.id` with PATCH. Managed fields cover RADIUS authentication/accounting, WPA2/WPA3 Enterprise security, management-frame protection, SSID visibility, static VLAN, client isolation, and client limits. The adapter does not delete records or create CAPsMAN provisioning rules because radio bands, bridge VLAN handling, and `wifi-qcom` versus `wifi-qcom-ac` behavior must be validated on the target hardware. RADIUS secrets are excluded from drift comparisons, so rotate them through a controlled RouterOS credential procedure.

UniFi remains an explicit AegisNAS contract adapter until its native resource client passes provider and hardware certification. All native adapters still require real-controller certification before production authority.

Example enterprise onboarding target with external CA and SAML admin access:

```yaml
deployment:
  profile: enterprise
  form: virtual
  hardware:
    memory_mb: 16384
    cpu_cores: 8
    storage_gb: 64
    prefer_external_ap: true

portal:
  enabled: true
  local_fallback: true
  guest_workflows:
    self_registration_enabled: true
    sponsor_approval_enabled: true
    approval_delivery: email
    email_from: access@example.com
    smtp_server: smtp.example.com
    smtp_port: 587

radius:
  eap:
    default_type: tls
    check_crl: false
    ca_path_reload_interval: 3600
    ocsp:
      enabled: true
      override_cert_url: true
      url: https://ca.example.com/ocsp
      use_nonce: true
      timeout_seconds: 5
      soft_fail: false

onboarding:
  device_inventory_enabled: true
  portal_enabled: true
  certificate_enrollment_enabled: true
  eap_tls_enabled: true
  ca_mode: external
  ca_enrollment_url: https://ca.example.com/api/enroll
  ca_enrollment_token_env: AEGIS_CA_ENROLLMENT_TOKEN

profiling:
  mac_inventory_enabled: true
  passive_enabled: true
  posture_enabled: true
  mdm_sync_enabled: true
  mdm_provider: workspace-one-like
  mdm_endpoint: https://mdm.example.com/api
  mdm_api_token_env: AEGIS_MDM_API_TOKEN
  compliance_webhook: https://policy.example.com/compliance
  compliance_token_env: AEGIS_COMPLIANCE_WEBHOOK_TOKEN

integrations:
  admin_sso:
    enabled: true
    provider: saml
    issuer_url: https://idp.example.com/metadata
    client_id: aegisnas-admin
    redirect_url: https://admin.example.com/auth/callback
    groups_claim: groups
```

## Runtime Behavior

The current profile-aware implementation changes behavior in these concrete ways:

- telemetry can be disabled cleanly
- AI Lite can be disabled cleanly
- runtime shaping can be disabled cleanly
- guest workflow, onboarding, and profiling capability states are previewed before save
- guest self-registration and sponsor approval also run end to end through the captive portal and Guest Requests admin view once the workflow is enabled
- onboarding now supports internal and external CA enrollment paths plus certificate inventory, revoke, renew, and internal-CA CRL operations
- MDM and compliance posture inputs can use environment-backed bearer tokens
- passive DHCP profiling feeds device inventory with hostname, DHCP client ID, MAC OUI, profile risk score, and risk reasons; trusted collectors can add user-agent, DHCP fingerprint, LLDP, and CDP observations through `/api/v1/devices/profile-observations`; high-risk active sessions can be moved into `quarantine-profile-risk` when posture remediation is enabled
- impossible onboarding and profiling combinations are rejected during validation
- integration and governance capability states are previewed before save
- impossible controller, SSO, SIEM, delegated-admin, and multi-tenant combinations are rejected during validation
- admin SSO runs end to end with OIDC or SAML plus break-glass token fallback
- SIEM export, controller automation, delegated admin, and tenant-aware scoping all have live runtime support
- the dashboard shows profile, CPU/RAM/storage hints, scaling mode, retention targets, and mismatch warnings
- the admin UI can apply profile defaults directly into the live config editor

The profile system does not try to magically make every hardware target run every feature. Instead, it gives the operator a safe way to scale the product down or up while keeping one codebase and one admin workflow.

For high-configuration appliances, use `deployment.profile: enterprise` with `ailite.mode: full` and an OpenAI-compatible endpoint. See [Full AI Engine](full-ai-engine.md).
