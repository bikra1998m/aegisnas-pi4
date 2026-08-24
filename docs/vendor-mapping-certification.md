# NAS-0060 Vendor Mapping Certification

NAS-0060 closes the software engineering gap for the 141 mappings that are
`partial` in the pinned FreeRADIUS 3.2.8 VSA audit registry.

Engineering completion means AegisNAS can prove each mapping has deterministic
software evidence. It does not mean the mapping is externally certified on real
vendor hardware or customer production networks.

## Software Certification Scope

The certification report is built from code and release-bound data:

- `configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv`
- generated typed registry state
- compatibility evidence dimensions
- semantic policy registry
- packet codec and generated inbound decoder metadata
- reply rendering coverage where the mapping has `outbound_reply`
- storage history in `vendor_mapping_certification_events`
- enforcement owner classification
- admin API, UI, readiness, status, and support-bundle visibility

The baseline count is fixed at 141 for this release. Validation fails if the
report has fewer or more rows, any required software dimension is blocked, or
any row claims external certification without release evidence.

## API

```text
GET  /api/v1/system/vendor-mapping-certification
POST /api/v1/system/vendor-mapping-certification/record
GET  /api/v1/system/vendor-mapping-certification/history
```

`GET` returns the current derived report and recent persisted events. `POST`
records the current fingerprint, summary, full report, actor, and timestamp.
`history` returns the event summary and recent event rows.

## Database

Schema v65 adds:

```text
vendor_mapping_certification_events
```

Each event stores release profile ID, registry source hash, baseline count,
certified count, blocker count, external-required count, vendor count,
fingerprint, summary JSON, full report JSON, actor, and creation time.

The database is an evidence ledger. The current certification truth is always
re-derived from the pinned registry and code so stale rows cannot silently
upgrade or downgrade software claims.

## Operations

Run this after upgrading or changing vendor compatibility code:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-mapping-certification | jq '.report.summary'
```

Record the current evidence snapshot after tests pass:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-mapping-certification/record | jq '.event_id, .status'
```

Production readiness includes `vendor_mapping_certification`. System status
includes `radius.vendor_mapping_certification`. Support bundles include:

- `api/vendor-mapping-certification.json`
- `api/vendor-mapping-certification-history.json`

## External Release Boundary

The 141 mappings are marked ready for external validation, not externally
certified. Complete
[nas-0060-release-certification-checklist.md](nas-0060-release-certification-checklist.md)
before publishing hardware-certified or customer-certified compatibility
claims.

## Automated Tests

```bash
make test-vendor-mapping-certification
```

The target covers the generated certification report, schema migration, DB
ledger, admin APIs, RBAC, OpenAPI, readiness, and support-bundle capture
registration.
