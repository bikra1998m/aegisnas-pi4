# Controller Estate And Object Lifecycle

NAS-0078 adds controller estate lifecycle governance for external WLAN
controllers. It turns the configured controller adapter, SSID intent, RADIUS
references, and runtime sync evidence into a redacted inventory and object plan.

## Purpose

The lifecycle prevents controller drift from becoming invisible operational
state. Operators can preview the controller estate before pushing policy, see
which objects AegisNAS owns, verify delete guards, and record an apply
checkpoint without assuming that real controller firmware validation has
already happened.

## Covered Software Scope

- Adapter catalog coverage for generic REST, Cisco, Aruba, Juniper Mist,
  Ruckus, Fortinet, MikroTik, UniFi, Meraki, and TIP OpenWiFi.
- Redacted configured-state evidence for endpoint, site, sync mode, credential
  environment names, credential presence, RADIUS profile, RADIUS server, and
  RADIUS shared-secret reference.
- Controller inventory objects for controller scope, adapter capabilities,
  credential references, RADIUS references, and configured WLANs.
- WLAN templates derived from `wireless.ssids` including authentication mode,
  VLAN, dynamic VLAN, guest portal, roaming, Passpoint, PPSK, bandwidth, and
  identity-source references.
- Object plans for inventory read, observe, upsert, delete protection, and
  rollback checkpoint behavior.
- Compliance checks for controller enablement, endpoint, site scope, credential
  references, WLAN templates, adapter capability coverage, drift preview, delete
  safety, rollback checkpoint, firmware evidence tracking, and local/controller
  ownership boundaries.
- Durable event history in `controller_estate_lifecycle_events`.
- Admin API, OpenAPI, RBAC, system status, production readiness, support bundle,
  Admin UI, Makefile, and CI coverage.

## API

- `GET /api/v1/system/controller-estate-lifecycle`
- `POST /api/v1/system/controller-estate-lifecycle/preview`
- `POST /api/v1/system/controller-estate-lifecycle/apply`
- `GET /api/v1/system/controller-estate-lifecycle/history?limit=100`

Read-only and guest-admin users may read and preview. Ops-admin and super-admin
users may apply. Apply records an auditable lifecycle checkpoint and runtime
status; destructive controller deletes are not performed automatically.

## Operating Flow

1. Configure `integrations.controller` with the target platform, endpoint,
   credential environment references, sync mode, and site when required.
2. Keep `wireless.enabled: false` for controller-owned WLAN estates. SSID intent
   may still be configured and is rendered into controller templates.
3. Run the controller estate preview from Access Settings or the API.
4. Review inventory objects, WLAN templates, compliance checks, delete guards,
   desired-state hash, and plan fingerprint.
5. Apply the lifecycle checkpoint after review.
6. Use `controller-sync/preview` and confirmed `controller-sync` operations for
   external controller pull/push behavior.

## External Release Certification

Engineering completion does not require real controllers. The following proof is
tracked separately in `docs/nas-0078-release-certification-checklist.md`:

- controller firmware/API compatibility
- physical AP inventory reconciliation
- packet captures
- delete simulation on real estates
- HA failover
- scale and soak results
- security audit
- production deployment
- customer acceptance
