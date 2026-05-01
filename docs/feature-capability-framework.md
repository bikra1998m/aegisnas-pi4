# Feature Capability Framework

This document defines how AegisNAS should enable, warn on, degrade, or block features based on hardware, deployment form, and integration readiness.

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

The current codebase already has an early form of this model through:

- deployment profiles
- deployment form
- hardware hints
- dashboard mismatch warnings
- profile-driven defaults for AI, telemetry, shaping, and RADIUS scale

That work lives primarily in:

- `internal/config/profile.go`
- `internal/config/config.go`
- `web/admin-ui/src/pages/AccessSettings.tsx`
- `web/admin-ui/src/pages/Dashboard.tsx`

This framework extends that idea to the rest of the product.

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
| Dynamic VLAN SSIDs | available | enabled | enabled | strongest on enterprise gear |

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
| Guest self-registration | blocked | available | enabled | needs workflow UI and notification plumbing |
| Sponsor approval | blocked | available | enabled | needs approval flow and audit model |
| Email or SMS invite | blocked | warned | enabled | depends on provider setup |
| Guest lifecycle reporting | available | enabled | enabled | stronger value on branch and enterprise |

Rules:

- sponsor approval should be `blocked` unless email or approval transport is configured
- self-registration should not be shown as ready if portal pages and approval destinations are incomplete

### 4. BYOD And Onboarding

These features separate a serious NAC suite from a basic portal appliance.

| Feature | Lite | Branch | Enterprise | Notes |
| --- | --- | --- | --- | --- |
| Device registration inventory | blocked | available | enabled | useful base layer |
| Onboarding portal | blocked | warned | enabled | needs UX, cert, and role flow |
| Certificate enrollment | blocked | blocked | enabled | requires CA model |
| EAP-TLS onboarding | blocked | blocked | enabled | needs strong certificate handling |
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
| Passive device profiling | blocked | warned | enabled | needs collector and rule set |
| Endpoint posture checks | blocked | blocked | enabled | requires integrations and agent model |
| MDM or UEM compliance ingest | blocked | blocked | enabled | integration-heavy |
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
| Runtime shaping | warned | enabled | enabled | depends on downstream interface and hardware |
| Quarantine enforcement | enabled | enabled | enabled | already present |
| ACL-like policy language | blocked | available | enabled | major next-step feature |
| Vendor-aware enforcement adapters | blocked | available | enabled | needed for stronger multivendor parity |

Rules:

- shaping should be `blocked` if no shaping interface exists
- ACL-like policy should not be presented as complete until device-side enforcement adapters exist

### 7. Identity And Enterprise Integrations

| Feature | Lite | Branch | Enterprise | Notes |
| --- | --- | --- | --- | --- |
| LDAP auth | available | enabled | enabled | already present |
| Upstream RADIUS / AAA | available | enabled | enabled | already present |
| Local fallback | enabled | enabled | enabled | already present |
| SAML or OIDC admin auth | blocked | available | enabled | future work |
| MDM or UEM integration | blocked | blocked | enabled | future work |
| SIEM / webhook export | available | enabled | enabled | can scale by retention depth |
| Multi-tenant separation | blocked | blocked | available | future work |

### 8. Operations And Governance

| Feature | Lite | Branch | Enterprise | Notes |
| --- | --- | --- | --- | --- |
| Dashboard and service health | enabled | enabled | enabled | already present |
| Alerts | available | enabled | enabled | already present |
| Revisions / staged apply / rollback | enabled | enabled | enabled | already present |
| Backup and restore | enabled | enabled | enabled | already present |
| AI recommendations | blocked | enabled | enabled | existing profile system already trends this way |
| Full AI mode | blocked | warned | enabled | requires configured provider |
| Delegated admin / RBAC | blocked | available | enabled | future work |
| Rich reporting and analytics | warned | available | enabled | future work |

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

Add stronger guest workflow gating:

- self-registration
- sponsor approval
- portal transport dependencies

Phase 2 adds production-grade guest workflow controls under `portal.guest_workflows`:

- `self_registration_enabled`
- `sponsor_approval_enabled`
- `invite_delivery`
- `approval_delivery`
- SMTP transport settings for email delivery
- SMS provider and endpoint settings for text delivery

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
- EAP-TLS onboarding requires certificate enrollment plus `radius.eap.default_type: tls`
- passive profiling requires MAC inventory and a poll interval of at least 30 seconds
- posture checks are enterprise-only and require MAC inventory plus an MDM endpoint or compliance webhook

This phase is the production foundation for BYOD and profiling. It does not claim that full certificate issuance, live onboarding transactions, or posture collectors already exist end to end. What it does give us is a safe config model, previewable feature state, and hard validation that prevents deployers from turning on workflows the appliance cannot support yet.

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
- admin SSO requires provider, issuer or metadata URL, client ID, and redirect URL
- SIEM export requires provider, endpoint, API key env, and positive batch size
- controller automation requires platform, endpoint, API token env, sync mode, and the external AP model
- delegated admin requires admin SSO or LDAP, and external-group RBAC requires a groups claim or LDAP group mapping
- multi-tenant governance is enterprise-only and requires delegated admin; when admin SSO is active it also needs a tenant claim

This phase makes the integration story deployable without pretending that every downstream connector is fully implemented. It gives operators a truthful model for what can be turned on safely, what still belongs to enterprise hardware, and what dependencies must exist before a production rollout should trust those integrations.

## Product Positioning Outcome

If this framework is implemented cleanly, AegisNAS can become:

- simple enough for lab VMs
- safe enough for low-power appliances
- strong enough for real branch deployments
- expandable enough for enterprise NAC growth

That is a better product direction than trying to clone each vendor suite one feature page at a time.
