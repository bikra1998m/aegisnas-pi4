# Production Readiness Update

Date: 2026-05-02

## Scope Of This Update

This document rolls up the production-readiness work completed across the project from the initial stabilization pass through the phase-based capability, onboarding, and integration work.

It reflects the current repository state after:

- core build and CRUD stabilization
- deployment capability gating across phases 1 to 4
- guest self-registration and sponsor approval runtime
- onboarding, device inventory, certificate enrollment, profiling, and posture runtime
- SIEM export, admin SSO, delegated admin, multi-tenant scoping, and controller automation runtime

## Readiness Journey

### 1. Core Platform Stabilization

The earliest production blockers were build, packaging, and day-two operations issues. Those are now resolved in the mainline product:

- pure-Go SQLite support for CGO-free builds
- stable Go and UI builds on the current workspace
- CRUD coverage for the main admin objects
- real staged apply, rollback, backup, and restore paths
- safer token auth, CORS defaults, and revision handling
- structured logging and audit coverage

### 2. Deployment Capability Gating

The product now uses a profile-aware capability model instead of treating every lab VM and every enterprise appliance as if they should run the same feature set.

That means the product can now:

- allow, warn, degrade, or block features based on hardware and deployment form
- reject impossible combinations during config validation
- preview capability state directly in `Access Settings`
- surface deployment mismatch and runtime state on the dashboard

This covers:

- wireless passthrough expectations for VMs
- runtime shaping
- AI mode selection
- telemetry
- guest workflows
- onboarding and profiling
- integrations and governance

### 3. Guest Workflow Runtime

Guest access is now more than a simple token-or-voucher login page.

The repo now includes end-to-end guest workflow runtime for:

- captive portal self-registration
- sponsor approval by email or SMS
- guest request review in the admin UI
- local guest credential minting after approval
- audit and alert generation for failed delivery paths

Operational UI pages now include:

- `Guest Requests`
- `Users`
- `Vouchers`
- `Portal Profiles`

### 4. Onboarding And Profiling Runtime

The onboarding path is now a real runtime, not only a gated future feature.

Current runtime coverage includes:

- device inventory
- onboarding portal flow
- certificate download from the admin UI
- internal CA enrollment
- external CA enrollment through a JSON API
- EAP-TLS onboarding gating
- passive device inventory and profiling hooks
- posture synchronization from MDM or compliance webhook inputs
- quarantine action when posture marks a device non-compliant

The current implementation supports both:

- `onboarding.ca_mode: internal`
- `onboarding.ca_mode: external`

External CA mode now supports an optional bearer token sourced from:

- `onboarding.ca_enrollment_token_env`

The admin UI now includes:

- `Devices`

### 5. Integration And Governance Runtime

Phase 4 moved from capability preview into real runtime for the declared production paths.

Current runtime coverage includes:

- OIDC admin SSO
- SAML admin SSO
- break-glass token fallback for admin access
- delegated admin roles
- tenant-aware admin scoping
- SIEM export to `webhook`, `splunk-hec`, or `elastic`
- controller automation as a live background sync loop
- runtime status surfacing for SSO, SIEM, and controller automation

The admin UI now includes:

- `Admin Access`

The dashboard now reports live status for:

- admin SSO
- SIEM export
- controller automation

## Security And Secret Handling Improvements

The current product guidance now assumes secret-bearing integrations use environment variables or protected files instead of being embedded casually in docs or workflows.

Important runtime secret paths now include:

- `AEGIS_ADMIN_BOOTSTRAP_TOKEN`
- `AEGIS_ADMIN_ALLOWED_ORIGINS`
- `AEGIS_REVISION_SIGNING_KEY`
- `AEGIS_AI_API_KEY`
- `AEGIS_CA_ENROLLMENT_TOKEN`
- `AEGIS_MDM_API_TOKEN`
- `AEGIS_COMPLIANCE_WEBHOOK_TOKEN`
- `AEGIS_SIEM_API_KEY`
- `AEGIS_CONTROLLER_API_TOKEN`
- `AEGIS_ADMIN_SSO_CLIENT_SECRET`

## Verification Completed

Repository verification completed against the current code:

```powershell
go test ./...
```

Result: pass.

```powershell
cd web/admin-ui
npm run build
```

Result: pass.

## Production Deployment Standard

The repository is now in a good state for:

- lab deployment
- pilot deployment
- staged customer deployment on supported hardware

The current product standard assumes:

- the deployment profile matches the hardware class
- real site secrets and certificates are supplied
- integration endpoints are reachable and tested
- at least one backup and restore drill is performed before production sign-off
- at least one login-path acceptance run is captured with the debug bundle workflow

Operators can now verify those assumptions through the live production readiness endpoint:

```text
/api/v1/system/production-readiness
```

The report returns an explicit `ready`, `warned`, `degraded`, or `blocked` status with checks for configuration validation, hardware scaling, AegisNAS vendor identity, placeholder PEN use, product dictionary detection, vendor pack coverage, NAS profile coverage, active feature gates, controller readiness, and live vendor runtime evidence.

## Remaining Product Boundaries

This document is intentionally honest about what "ready" means.

The current repo is strong for the implemented product paths, but a few boundaries still matter:

- controller automation is a vendor-neutral sync contract, not one-to-one native parity with every controller API
- rich long-horizon reporting is still lighter than large NAC suites
- external MDM, compliance, SAML, and CA paths still need real customer-environment validation during deployment

Those are deployment and ecosystem realities, not missing code blockers for the current declared feature set.

## Current Status

The repository is no longer in a phase-preview state.

Current status:

- core platform: production-capable
- guest workflows: end to end
- onboarding and certificate workflows: end to end
- profiling and posture inputs: end to end
- admin SSO: OIDC and SAML end to end
- delegated admin and tenant scoping: end to end
- SIEM export: end to end
- controller automation: end to end within the declared vendor-neutral contract

The next step after this repo state is always environment validation:

- pull the latest code to the target VM or appliance
- run migration and redeploy
- execute the runbooks in `docs/ubuntu-vm-runbook.md`, `docs/vmware-workstation-17-player-full-test.md`, and `docs/login-test-runbook.md`
