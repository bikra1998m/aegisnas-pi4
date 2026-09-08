# NAS-0073 External Vendor Intake

NAS-0073 is the software path for vendor dictionaries that are not part of the
pinned FreeRADIUS 3.2.8 corpus. It covers authoritative dictionary intake,
provenance, PEN validation, licensing, semantic classification, packet safety,
redaction, API/UI visibility, durable evidence, and release boundary tracking.

It does not turn an external vendor into a hardware-certified product claim.
Device, controller, FreeRADIUS production Linux, HA, performance, soak,
security, customer, and compliance proof stay in
[nas-0073-release-certification-checklist.md](nas-0073-release-certification-checklist.md).

## Scope

Use this flow for:

- Ubiquiti/UBNT dictionaries that are not present in the pinned FreeRADIUS
  source tree
- Netgear or other vendors outside the pinned corpus
- future vendor dictionaries received from a vendor, integrator, or customer

Do not use this flow for a vendor already present in the pinned FreeRADIUS
release. In-corpus vendors must use their focused pack or the NAS-0072
long-tail namespace program.

## Required Evidence

Every intake request must include:

- `vendor_name`
- `pen`
- `dictionary_text`
- `source_url`
- `source_sha256`
- `license_id`
- `license_reference`
- `upstream_version`
- `retrieved_at`

Accepted source references are HTTPS, Git HTTPS, or a URN SHA-256 authority.
Accepted license identifiers are exposed by:

```text
GET /api/v1/system/external-vendor-intake
```

The server recomputes SHA-256 over the trimmed dictionary text and rejects a
record if it does not match `source_sha256`.

## API

```text
GET  /api/v1/system/external-vendor-intake
POST /api/v1/system/external-vendor-intake/preview
POST /api/v1/system/external-vendor-intake/record
GET  /api/v1/system/external-vendor-intake/history
```

Read-only roles can inspect governance and history. `ops_admin` and
`super_admin` can preview and record intake evidence.

Preview is non-mutating. Record persists a bounded report in
`external_vendor_intake_events`; raw `dictionary_text` is parsed and
fingerprinted but is not stored in the event report.

## Packet And Policy Handling

The intake parser supports FreeRADIUS-style `VENDOR`, `BEGIN-VENDOR`,
`END-VENDOR`, `ATTRIBUTE`, and `VALUE` directives. Each attribute receives:

- vendor and PEN identity
- numeric type or OID
- wire type and codec metadata
- semantic family
- packet-processing state
- policy-engine state
- persistence state
- redaction state for secret-like attributes
- explicit external certification boundary

Numbered VSAs in the byte-sized range `1..255` can be represented as bounded
runtime-decoding candidates. `internal/radius.ExternalVendorIntakeVSASpecs`
converts a validated report into generic VSA codec specs for packet capture and
interoperability tests; blocked reports cannot produce specs. OID, TLV,
extended, grouped, or unsupported encodings remain metadata-only until a
focused adapter implements them.

## Operator Flow

1. Obtain the dictionary from an authoritative vendor or integrator source.
2. Verify the vendor PEN against IANA or the vendor's published record.
3. Confirm redistribution or use rights.
4. Compute the SHA-256 of the exact dictionary text.
5. Preview the intake:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data @external-vendor-intake.json \
  http://127.0.0.1:8083/api/v1/system/external-vendor-intake/preview | jq '.status, .report.summary, .report.blockers'
```

6. Resolve all blockers.
7. Record the software evidence:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data @external-vendor-intake.json \
  http://127.0.0.1:8083/api/v1/system/external-vendor-intake/record | jq '.event_id, .status'
```

8. Run the focused gate:

```bash
make test-external-vendor-intake
```

9. Execute the release certification checklist before publishing hardware
   compatibility claims.

## Production Readiness

`/api/v1/system/production-readiness` includes
`external_vendor_intake`. `/api/v1/system/status` exposes the same state under
`radius.external_vendor_intake`.

Software implementation is complete when the governance report validates,
automated tests pass, API/UI evidence is available, and the release checklist
contains every external validation activity.
