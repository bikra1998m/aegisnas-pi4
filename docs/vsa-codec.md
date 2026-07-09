# VSA Codec

Feature: `NAS-0005`

Status: engineering implementation complete; ready for external validation.

## Purpose

NAS-0005 provides the packet foundation for broad vendor compatibility. AegisNAS can now decode and encode RFC 2865 Vendor-Specific Attributes with:

- repeated values across multiple Vendor-Specific attributes
- multiple packed vendor attributes inside one Vendor-Specific payload
- FreeRADIUS-style vendor formats with 1, 2, or 4 type octets and 0, 1, or 2 length octets
- tagged vendor attributes with bounded tag validation
- grouped and OID-backed attributes used by WiMAX, 3GPP2, telecom, and similar dictionaries
- deterministic malformed-length errors instead of silent fallback

This is software codec readiness. It does not certify every vendor feature or every physical device.

## Standards

- RFC 2865: RADIUS and Vendor-Specific Attribute framing.
- FreeRADIUS dictionary conventions: `VENDOR`, `BEGIN-VENDOR`, `ATTRIBUTE`, OID paths, grouped/TLV attributes, and `format=t,l` vendor payload layouts.

Later domain features still own behavior for mobile charging, WiMAX service flows, BNG subscriber management, lawful intercept, voice, cable, and other vendor-specific workflows.

## API

```text
GET /api/v1/system/vsa-codec
```

The response includes:

- schema, release profile, FreeRADIUS release, and registry source hash
- source, numeric, OID-backed, grouped, repeated, tagged, and runtime decoder counts
- supported vendor wire formats
- packet and payload limits
- notes separating software readiness from external certification

Example:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vsa-codec \
  | jq '.status, .summary, .supported_formats'
```

## Registry Contract

The typed attribute registry now exposes `oid_path` and `wire_codec` for each attribute. `wire_codec` records the default type/length format, repeated value support, grouped/OID state, tagged state, and extended/vendor state.

OID-backed attributes are represented without claiming their domain semantics are complete. For example, a WiMAX grouped child can be decoded as a bounded TLV/OID value while WiMAX subscriber policy remains scheduled for later mobile/broadband features.

## Readiness

Production readiness includes a `vsa_codec` check. It validates:

- codec schema version
- source registry count
- grouped/OID metadata presence
- supported format matrix
- read-only API visibility

External lab validation, packet captures, real FreeRADIUS transport tests, HA soak, and vendor hardware certification are tracked in the NAS-0005 release certification checklist.

## Validation

Run:

```bash
make test-vsa-codec
```

On Windows shells without `make`, run:

```powershell
go test ./configs ./internal/radius ./internal/adminapi -run 'VSACodec|VendorAttributeFormat|AttributeRegistry|GeneratedAttributeRegistry|Authorize|OpenAPI|ProductionReadiness' -count=1
```

## Completion Report

| Measure | Result |
|---|---:|
| Software Implementation | 100% Complete |
| Engineering Implementation | 100% Complete |
| Ready for External Validation | Yes |
| NAS-0005 status | Closed |

There is no remaining NAS-0005 software implementation work. External vendor, firmware, FreeRADIUS production transport, HA, performance, soak, security, and customer validation are tracked separately in the NAS-0005 release certification checklist.
