# Opaque Attribute Pass-through

Feature: `NAS-0006`

Status: engineering implementation complete; ready for external validation.

## Purpose

Opaque pass-through lets AegisNAS preserve RADIUS attributes that are not yet mapped into vendor-neutral semantics, without interpreting or executing them. This is useful for long-tail vendor dictionaries, controller correlation tokens, and upstream AAA attributes that must survive a proxy path while the product team builds native semantics later.

The feature is intentionally conservative:

- default action is always `drop`
- pass-through requires an explicit allow rule
- malformed VSAs are rejected
- byte, count, and replay limits are enforced
- credential, EAP, and integrity attributes are never treated as opaque data
- known native mappings are not passed opaquely unless a rule explicitly sets `allow_known`

## Standards

- RFC 2865: RADIUS packet and Vendor-Specific Attribute framing.
- FreeRADIUS dictionary conventions: vendor IDs, vendor attributes, and vendor payload formats.

This feature does not replace native RADIUS proxy routing, EAP handling, message-authenticator generation, or vendor feature certification.

## Configuration

The policy lives under `radius.vendor.opaque_pass_through`:

```yaml
radius:
  vendor:
    opaque_pass_through:
      enabled: true
      max_attributes_per_packet: 32
      max_attribute_bytes: 249
      max_total_bytes_per_packet: 2048
      rules:
        - direction: proxy_response
          kind: vendor_attribute
          vendor_id: 424242
          type: 77
          description: "Example lab controller correlation token"
```

Rule kinds:

- `standard`: allow one non-sensitive standard RADIUS type.
- `vendor`: allow unknown VSAs from one PEN.
- `vendor_attribute`: allow one vendor attribute type from one PEN.

Directions:

`any`, `inbound_request`, `outbound_reply`, `accounting_request`, `accounting_response`, `coa_request`, `coa_response`, `disconnect_request`, `disconnect_response`, `proxy_request`, and `proxy_response`.

Denied standard types include `User-Password`, `CHAP-Password`, `Vendor-Specific` as a standard rule, `CHAP-Challenge`, `Tunnel-Password`, `EAP-Message`, and `Message-Authenticator`.

## API

```text
GET /api/v1/system/opaque-passthrough
```

Example:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/opaque-passthrough \
  | jq '.status, .policy.default_action, .summary, .sensitive_types'
```

The response includes:

- schema, release profile, FreeRADIUS release, and registry source hash
- effective policy and limits
- allow-rule counts by standard type, vendor, and vendor attribute
- missing and partial registry counts that may later be governed by pass-through
- sensitive standard attribute denylist
- notes separating software readiness from external certification

## Packet Behavior

`CollectOpaqueAttributes` scans a packet, decodes VSAs through the shared NAS-0005 codec, and returns accepted records plus drops and errors. Accepted records store raw bytes and a SHA-256 digest; JSON reports never expose the raw payload.

`ApplyOpaqueAttributes` replays previously accepted records into another packet after revalidating the policy and byte budgets.

The collector preserves raw standard attribute values and raw vendor subattribute payloads. It does not interpret policy, mutate values, decrypt secrets, repair malformed VSAs, or claim the destination device will enforce the attribute.

## Readiness

Production readiness includes an `opaque_passthrough` check. It validates:

- schema version
- default action remains `drop`
- packet, attribute, total-byte, and replay limits are valid
- sensitive standard denylist is populated
- generated registry provenance is available

External proxy transport validation, FreeRADIUS production tests, vendor hardware, HA soak, performance, and customer acceptance are tracked in the NAS-0006 release certification checklist.

## Validation

Run:

```bash
make test-opaque-passthrough
```

On Windows shells without `make`, run:

```powershell
go test ./internal/config ./internal/radius ./internal/adminapi -run 'OpaquePassThrough|VendorConfig|Authorize|OpenAPI|ProductionReadiness' -count=1
```

## Completion Report

| Measure | Result |
|---|---:|
| Software Implementation | 100% Complete |
| Engineering Implementation | 100% Complete |
| Ready for External Validation | Yes |
| NAS-0006 status | Closed |

There is no remaining NAS-0006 software implementation work. External proxy, vendor, firmware, FreeRADIUS production transport, HA, performance, soak, security, and customer validation are tracked separately in the NAS-0006 release certification checklist.
