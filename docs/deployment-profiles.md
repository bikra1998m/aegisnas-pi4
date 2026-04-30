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
- suitable for most pilot and branch appliance builds

### `enterprise`

Use this when you have more hardware headroom and heavier auth or policy load.

Recommended direction:

- keep guest self-registration and sponsor approval on this tier when guest access is a customer-facing workflow
- configure SMTP or SMS delivery before enabling invites or sponsor approval
- treat this as the preferred tier for branded guest onboarding and approval-heavy guest programs

Recommended direction:

- full AI mode on when a provider endpoint and model are configured
- telemetry on
- runtime shaping on
- larger `radius.max_sessions`
- active upstream AAA probing

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

## Runtime Behavior

The current profile-aware implementation changes behavior in these concrete ways:

- telemetry can be disabled cleanly
- AI Lite can be disabled cleanly
- runtime shaping can be disabled cleanly
- the dashboard shows profile, hardware hints, and mismatch warnings
- the admin UI can apply profile defaults directly into the live config editor

The profile system does not try to magically make every hardware target run every feature. Instead, it gives the operator a safe way to scale the product down or up while keeping one codebase and one admin workflow.

For high-configuration appliances, use `deployment.profile: enterprise` with `ailite.mode: full` and an OpenAI-compatible endpoint. See [Full AI Engine](full-ai-engine.md).
