# Dynamic NAS Clients

Feature ID: NAS-0013

Dynamic NAS clients let APs, switches, gateways, and controllers request enrollment without giving every operator direct database or FreeRADIUS file access. The feature keeps unknown devices fail-closed, records discovery evidence, allows an operator to approve or reject the client, and writes the approved client into the authoritative RADIUS client inventory with secret references and capability metadata.

## Problem Solved

Traditional RADIUS deployments require every NAS client to be pre-created in FreeRADIUS `clients.conf` with an IP address, shared secret, NAS type, and optional RadSec certificate identity. That is safe but painful at enterprise scale. Dynamic enrollment solves the fleet-management side:

- branch APs and switches can request enrollment through a bounded bootstrap endpoint
- packet discovery records unknown sources without authenticating them
- operators approve clients only after checking source IP, model, firmware, capabilities, tenant, and credential reference
- approved clients become normal `radius_clients` records
- rejected, revoked, and expired enrollments remain auditable
- capability templates prevent a device from being approved for behavior it did not claim

Dynamic enrollment does not weaken packet handling. Unknown RADIUS packets are still rejected by packet hardening until the client is approved and present in the configured client inventory.

## Standards And Vendor Context

Dynamic client inventory is not a single RADIUS RFC feature. It is a product management layer around:

- RFC 2865: RADIUS authentication and NAS client identity fields
- RFC 2866: RADIUS accounting source identity
- RFC 5176: dynamic authorization ownership dependencies
- RFC 6614 and RFC 9813: RadSec and RADIUS over TLS deployment context

The capability model is vendor-neutral and applies to Cisco, Aruba/HPE, Juniper, Ruckus, Extreme, Fortinet, MikroTik, Ubiquiti, Cambium, TP-Link, Huawei/H3C, Nokia, and other access vendors represented in the FreeRADIUS dictionaries. Vendor-specific features still belong to later vendor-pack work; NAS-0013 provides the trusted device inventory those features depend on.

## Configuration

```yaml
radius:
  dynamic_clients:
    enabled: false
    discovery_enabled: false
    approval_required: true
    enrollment_token_ref: "env:AEGIS_NAS_ENROLLMENT_TOKEN"
    enrollment_ttl_seconds: 86400
    max_pending: 256
    discovery_allowed_cidrs: []
    default_nas_type: other
    default_transport: udp
    default_template: default
```

Production guidance:

- keep `approval_required: true`
- use `env:` or `file:` for `enrollment_token_ref`
- restrict `discovery_allowed_cidrs` before enabling packet discovery
- approve UDP clients with `secret_ref`, not inline secrets
- approve RadSec clients with certificate CN metadata and the fixed RadSec application secret

## Data Model

Schema v20 adds dynamic metadata to `radius_clients`:

- `dynamic_source`
- `enrollment_id`
- `capabilities_json`
- `vendor`
- `model`
- `firmware_version`
- `serial_number`
- `lifecycle_status`
- `last_seen_at`
- `approved_at`
- `approved_by`
- `owner_tenant`
- `template_name`

Schema v20 also adds:

- `nas_client_enrollments`: pending, approved, rejected, revoked, and expired enrollment lifecycle
- `nas_client_capability_templates`: required capability gates and allowed vendors
- `nas_client_events`: append-only lifecycle and discovery evidence

## APIs

Public bootstrap endpoint:

```text
POST /api/v1/nas/enroll
```

The request must include `X-AegisNAS-Enrollment-Token` or an `Authorization: Bearer` token that resolves from `radius.dynamic_clients.enrollment_token_ref`.

Operator endpoints:

```text
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

Read-only roles may list state. `ops_admin` and `super_admin` can create, approve, reject, revoke, and manage templates.

## Packet Processing

Packet hardening calls dynamic NAS discovery only after normal source validation determines the packet source is unknown. Discovery writes evidence but does not authenticate the packet. The packet is still rejected unless a static or approved dynamic client exists.

Known approved clients update heartbeat state with source IP, direction, packet code, and last-seen timestamp. This keeps inventory fresh without storing secrets or full packet payloads.

## Approval Flow

1. Device posts an enrollment request with source IP, shortname, NAS type, vendor/model/firmware/serial metadata, capabilities, tenant, template, and credential references.
2. The API validates the bootstrap token and prevents a remote source from enrolling a different source IP unless the request originates from loopback automation.
3. The enrollment is stored as `pending` with evidence hash and expiry.
4. An operator approves the enrollment with `secret_ref` or RadSec identity.
5. Capability template checks enforce required capability paths and optional allowed vendor names.
6. The approved enrollment creates or updates a `radius_clients` row with `dynamic_source: enrollment`.
7. Rejection, revocation, expiry, and heartbeat events remain in `nas_client_events`.

## Monitoring And Readiness

`/api/v1/system/status` includes `radius.dynamic_nas_clients` with policy, counters, recent event time, and warnings.

`/api/v1/system/production-readiness` includes `dynamic_nas_clients` and blocks risky configurations such as enabled enrollment without a token reference or automatic approval.

The Dashboard shows pending, approved, dynamic, static, and template counts. Access Settings exposes the dynamic-client policy. The RADIUS Clients page shows source, lifecycle, vendor, model, and last-seen metadata.

## Testing

Automated software validation includes:

- config validation for dynamic-client policy
- schema v20 migration and legacy repair
- enrollment approve/revoke/expiry lifecycle tests
- capability-template gate tests
- public enrollment token tests
- API inventory/status tests
- packet-hardening unknown-source discovery tests
- OpenAPI and RBAC tests
- production readiness tests

Focused command:

```bash
go test ./internal/config ./internal/db ./internal/radius ./internal/adminapi -run 'DynamicNAS|RadiusDynamicClients|NASClient|Migrate|OpenAPI|Authorize|ProductionReadiness|RadiusClient' -count=1
```

## Release Certification

Software implementation is complete when code, schema, APIs, UI, tests, docs, and CI are complete. Work requiring live devices, third-party systems, long-running labs, or external organizations is tracked separately in [NAS-0013 Release Certification Checklist](nas-0013-release-certification-checklist.md).
