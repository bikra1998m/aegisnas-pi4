# Compatibility Evidence Model

Feature: `NAS-0004`

Status: engineering implementation complete; ready for external validation.

## Purpose

NAS-0004 separates compatibility claims into explicit evidence dimensions. A single `implemented` flag is no longer treated as proof that a feature has dictionary metadata, typed registry mapping, packet decoding, reply rendering, policy wiring, local enforcement, UI/API visibility, and real vendor hardware certification.

The legacy `compatibility_state` field remains for backward compatibility. The authoritative software claim model is now the evidence record.

## Evidence States

Each mapping has:

- `software_state`: `ready`, `planned`, `blocked`, or `metadata_only`
- `certification_state`: `not_required`, `external_required`, or `certified`
- `claim_state`: `software_ready`, `software_ready_external_required`, `planned`, `blocked`, or `metadata_only`
- `dimensions`: dictionary metadata, typed registry, packet decode, reply renderer, policy wiring, and external certification
- `blockers` and `next_steps`

`software_ready` means AegisNAS code paths are wired for the declared software scope. It never means a physical AP, switch, firewall, controller, FreeRADIUS production build, HA deployment, or customer environment has been certified.

`external_required` means the engineering work is complete enough to enter lab validation, but release certification evidence is still needed before publishing a certified vendor claim.

## API

```text
GET /api/v1/system/compatibility-evidence
```

Filters:

- `pack`
- `vendor`
- `semantic`
- `software_state`
- `certification_state`
- `claim`
- `search`
- `limit`
- `cursor`

Example:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/compatibility-evidence?claim=software_ready_external_required' \
  | jq '.summary, .records[] | {pack_key, attribute, software_state, certification_state, claim_state}'
```

The Vendor Compatibility API also includes an `evidence` summary, and each semantic includes product-owned semantic evidence.

## Readiness

Production readiness includes a `compatibility_evidence` check. It validates schema version, release profile ID, source hash, record uniqueness, valid state values, and that no record claims external certification without a certification evidence store. Inactive long-tail vendor gaps are visible but do not degrade readiness. Active blocked records degrade readiness.

## Database And HA

NAS-0004 adds no database migration. Evidence is derived from immutable build-time registry data, dictionary release profile metadata, compatibility pack declarations, configured active packs, and imported dictionary coverage. HA nodes must run the same registry hash and release profile ID. Mutable signed certification records belong to later release-certification work.

## UI

The Vendor Compatibility page now includes a Compatibility Evidence panel with:

- software-ready, planned, blocked, metadata-only, and external-required counts
- filterable claim states
- per-attribute software and certification states
- evidence dimensions and blockers

## Validation

Run:

```bash
make test-compatibility-evidence
```

On Windows shells without `make`, run:

```powershell
go test ./configs ./internal/adminapi -run 'CompatibilityEvidence|VendorCompatibility|Authorize|OpenAPI|ProductionReadiness' -count=1
```

## Completion Report

| Measure | Result |
|---|---:|
| Software Implementation | 100% Complete |
| Engineering Implementation | 100% Complete |
| Ready for External Validation | Yes |
| NAS-0004 status | Closed |

There is no remaining NAS-0004 software implementation work. External vendor, firmware, HA, FreeRADIUS, performance, soak, security, and customer validation are tracked separately in the NAS-0004 release certification checklist.
