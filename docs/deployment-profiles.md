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
4. enter memory and CPU hints for the target box
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

## How To Use It In YAML

Example low-power edge appliance:

```yaml
deployment:
  profile: lite
  form: physical
  hardware:
    memory_mb: 1024
    cpu_cores: 4
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

portal:
  enabled: true
  local_fallback: true

radius:
  eap:
    default_type: tls

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
    endpoint: https://controller.example.com/api
    api_token_env: AEGIS_CONTROLLER_API_TOKEN
    sync_mode: monitor

governance:
  delegated_admin_enabled: true
  rbac_mode: hybrid
  external_groups_enabled: true
  multi_tenant_enabled: true
  tenant_claim: tenant
```

## Runtime Behavior

The current profile-aware implementation changes behavior in these concrete ways:

- telemetry can be disabled cleanly
- AI Lite can be disabled cleanly
- runtime shaping can be disabled cleanly
- guest workflow, onboarding, and profiling capability states are previewed before save
- impossible onboarding and profiling combinations are rejected during validation
- integration and governance capability states are previewed before save
- impossible controller, SSO, SIEM, delegated-admin, and multi-tenant combinations are rejected during validation
- the dashboard shows profile, hardware hints, and mismatch warnings
- the admin UI can apply profile defaults directly into the live config editor

The profile system does not try to magically make every hardware target run every feature. Instead, it gives the operator a safe way to scale the product down or up while keeping one codebase and one admin workflow.

For high-configuration appliances, use `deployment.profile: enterprise` with `ailite.mode: full` and an OpenAI-compatible endpoint. See [Full AI Engine](full-ai-engine.md).
