# Lossless Vendor-Neutral ACL AST

NAS-0048 adds a typed ACL abstract syntax tree (AST) that keeps rich vendor-neutral
policy intent intact while still producing the existing flat RADIUS ACL rule
projection for current vendor reply paths.

## Scope

Implemented software scope:

- Versioned ACL AST schema v1 with stable policy fingerprints.
- Flat-rule compatibility projection from AST to `acl_rules`.
- Backward-compatible AST derivation from existing flat ACL policies.
- Object groups, service groups, application groups, URL category groups,
  rule IDs, sequences, address family, source and destination lists, object
  references, source and destination ports, applications, URL categories, TCP
  flags, ICMP types, DSCP marks, time ranges, tags, metadata, and logging flags.
- Round-trip diagnostics when a rich AST field cannot be represented losslessly
  by current flat RADIUS reply attributes.
- Persisted AST JSON, fingerprint, and diagnostics on `acl_policies`.
- Staged create/update/apply and rollback support through existing config
  revision snapshots.
- Admin API normalization and reporting endpoints.
- Vendor reply preview enrichment with ACL AST, fingerprint, diagnostics,
  round-trip status, and per-pack lossless state.
- Admin UI ACL policy editor support for raw JSON AST input and table-level
  AST/round-trip status.
- Production readiness and support bundle evidence.

External hardware certification for exact controller grammars is tracked in
`nas-0048-release-certification-checklist.md` and does not block engineering
completion.

## Data Model

Schema v53 adds these columns to `acl_policies`:

- `ast_schema_version`
- `ast_json`
- `ast_fingerprint`
- `ast_diagnostics_json`

`rules_json` remains the compatibility projection consumed by existing RADIUS
reply renderers. When `acl_ast` is omitted, AegisNAS derives an AST from
`rules_json`. When `acl_ast` is present, it is the source of truth and
`rules_json` is regenerated from the AST projection.

## API

Use the ACL policy library for persisted policy lifecycle:

```text
GET    /api/v1/acl-policies
POST   /api/v1/acl-policies
PUT    /api/v1/acl-policies/{id}
DELETE /api/v1/acl-policies/{id}
POST   /api/v1/validate
POST   /api/v1/apply
```

Create or update requests may include `acl_ast` as an object or JSON string. The
response includes:

- `acl_ast`
- `ast_fingerprint`
- `ast_diagnostics`
- `acl_round_trip`

Use the normalization endpoint to validate intent without staging a change:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data @acl-policy.json \
  http://127.0.0.1:8083/api/v1/system/acl-ast/normalize | jq .
```

Use the status endpoint to audit all stored ACL policies:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/acl-ast \
  | jq '.report.status, .report.summary, .report.policies[] | {name, lossless, ast_fingerprint}'
```

The vendor reply preview accepts the same optional `acl_ast` field:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"nas_type":"cisco","acl_policy_name":"guest-web"}' \
  http://127.0.0.1:8083/api/v1/system/vendor-reply-preview \
  | jq '.acl_fingerprint, .acl_round_trip, .acl_exports'
```

## Round-Trip Diagnostics

AegisNAS treats the ACL AST as lossless source intent. Current RADIUS reply
attributes are narrower than the AST, so unsupported projections are reported
instead of silently discarded. Common diagnostics include:

- `object_group_expanded`
- `service_group_expanded`
- `field_not_rendered`
- `action_degraded`
- `direction_expanded`
- `compatibility_rules_differ`

A policy is `lossless: false` when any warning marks an AST field that current
flat ACL replies cannot carry exactly. Operators should certify the target
vendor compiler before enabling those fields in enforce mode.

## Security And HA

ACL AST payloads are validated before staging or preview. Invalid actions,
directions, address families, protocols, addresses, groups, metadata keys,
oversized rule sets, and unsupported schema versions are rejected. Fingerprints
are deterministic and safe to include in audit logs and support bundles.

The feature is HA-compatible because AST state is persisted in the primary
database and included in config revision snapshots. External HA validation for
controller/device behavior remains part of release certification.

## Testing

Automated coverage includes:

- AST normalization from flat rules.
- Rich AST preservation and diagnostics.
- ACL policy staging, apply, list, status, normalize, and vendor preview.
- Migration coverage for schema v53.
- Existing ACL renderer regression tests.
- Admin UI build validation.

Real AP, switch, controller, FreeRADIUS Linux packet capture, long soak,
performance, and security audit evidence belong in the release certification
checklist.
