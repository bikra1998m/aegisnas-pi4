# Certified Per-Vendor ACL Compilers And Decompilers

NAS-0049 adds a production software layer between the vendor-neutral ACL AST and
vendor RADIUS reply attributes. The compiler catalog is explicit about what can
be rendered as line rules, what can only be represented as a named profile
reference, and what must fail closed until a certified compiler exists.

## Scope

Implemented software scope:

- Compiler catalog with schema version `1` and compiler version `nas-0049.1`.
- Software-certified line-rule compilers and decompilers for:
  - Standard RADIUS `NAS-Filter-Rule`
  - AegisNAS `AegisNAS-ACL-Name` and `AegisNAS-ACL-Rule`
  - Cisco `Cisco-In-ACL`, `Cisco-Out-ACL`, and `Cisco-AVPair`
  - Aruba `Aruba-NAS-Filter-Rule`
  - HP/ArubaOS-Switch `Ip-Filter-Raw`
  - D-Link `ACL-Profile` and `ACL-Rule`
  - Pica8 `IP-Downloadable-ACL-Name` and `IP-Downloadable-ACL-Rule`
- Profile-reference compiler and decompiler support for vendors whose RADIUS
  path carries a policy name rather than portable line rules:
  - MikroTik `Mikrotik-Address-List` and `Mikrotik-Switching-Filter`
  - Fortinet `Fortinet-Access-Profile`
  - Ruckus `Ruckus-User-Groups`
  - Juniper `Juniper-Firewall-filter-name` and `Juniper-Switching-Filter`
  - Huawei `Huawei-Data-Filter`
  - H3C `H3C-Ita-Policy`
- Fail-closed unsupported pack handling for vendors such as Palo Alto when ACL
  intent is requested but no certified RADIUS ACL compiler exists in this
  release.
- Per-pack limits for rule count, attribute count, and RADIUS value byte size.
- Deterministic artifact fingerprints, FreeRADIUS text output, diagnostics,
  warnings, and lossless/non-lossless round-trip status.
- Decompile API for vendor ACL attributes back into neutral ACL rules or
  profile references.
- Durable compiler/decompiler evidence history in `acl_compiler_events`.
- Admin API, OpenAPI, RBAC, production-readiness, support-bundle, and admin UI
  visibility.

External device, controller, FreeRADIUS Linux packet-capture, HA, performance,
soak, security, and customer validation is tracked in
`nas-0049-release-certification-checklist.md` and does not block engineering
completion.

## Semantics

Line-rule compilers are marked `software-certified` when AegisNAS can:

1. Normalize ACL intent through the ACL AST and flat compatibility projection.
2. Render deterministic vendor attributes with bounded value lengths.
3. Decompile the generated attributes back to wire-equivalent ACL rules.
4. Report exact diagnostics instead of silently dropping unsupported intent.

Profile-reference compilers are marked `profile-reference`. They preserve the
policy name in RADIUS, but the actual rule contents must already exist on the
controller or device. If line rules are present, the result is intentionally
`lossless: false` with `profile_reference_only` diagnostics.

Unsupported packs are marked `unsupported`. If ACL intent is present, compile
returns `blocked` and emits no ACL attributes.

## API

Inspect compiler capabilities and recent evidence:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/acl-compilers \
  | jq '.report.status, .report.summary, .report.capabilities[] | {pack_key,status,certification_state,attributes}'
```

Compile ACL intent without applying it:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_name":"guest-internet",
    "inbound_acl":"guest-in",
    "outbound_acl":"guest-out",
    "pack_keys":["standard","cisco","mikrotik","paloalto"],
    "rules":[
      {"action":"permit","direction":"in","protocol":"tcp","source":"any","destination":"any","destination_port":"443"},
      {"action":"deny","direction":"out","protocol":"udp","source":"any","destination":"10.0.0.0/24","destination_port":"53"}
    ]
  }' \
  http://127.0.0.1:8083/api/v1/system/acl-compilers/compile \
  | jq '.run.status, .run.summary, .run.results[] | {pack_key,status,lossless,artifact_fingerprint,diagnostics}'
```

Decompile vendor ACL attributes:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "pack_key":"cisco",
    "policy_name":"guest-internet",
    "attributes":[
      {"name":"Cisco-AVPair","value":"ip:inacl#1=permit tcp any any eq 443","quoted":true}
    ]
  }' \
  http://127.0.0.1:8083/api/v1/system/acl-compilers/decompile \
  | jq '.result.status, .result.rules, .result.profile_references'
```

List durable evidence:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/acl-compilers/history \
  | jq '.summary, .history[0:10]'
```

All endpoints are preview/evidence operations. They do not push rules to a
controller or alter live sessions.

## Database

Schema v54 adds `acl_compiler_events`:

- `event_id`
- `operation`
- `status`
- `pack_key`
- `policy_name`
- `ast_fingerprint`
- `artifact_fingerprint`
- `artifact_count`
- `rule_count`
- `lossless`
- `diagnostics_json`
- `details_json`
- `actor`
- `created_at`

The table records compile and decompile evidence for support bundles,
production readiness, and release certification. It intentionally stores
diagnostics and fingerprints instead of sensitive packet bodies.

## Operations

Use `/api/v1/system/vendor-reply-preview` for the normal operator preview path.
Its `acl_exports` entries now include compiler status, compiler version,
certification state, limits, lossless state, artifact fingerprint, diagnostics,
warnings, attributes, and FreeRADIUS output.

Use `/api/v1/system/acl-compilers/compile` when validating compiler behavior
independently of a full RADIUS reply. Treat `blocked` as fail-closed. Treat
`profile_reference` as a requirement to validate matching controller or device
policy names before production.

Support bundles include:

- `api/acl-compilers.json`
- `api/acl-compiler-history.json`

Production readiness includes the `acl_compilers` check. Blocked or unsupported
evidence degrades readiness until reviewed.

## Testing

Automated software coverage includes:

- Golden compiler/decompiler round trips for all software-certified line-rule
  packs.
- Profile-reference diagnostics and decompile behavior.
- Unsupported vendor fail-closed behavior.
- RADIUS value size limit blocking.
- Vendor reply rendering regression.
- Admin API compile, decompile, history, readiness, RBAC, OpenAPI, and support
  bundle tests.
- Migration and evidence-history tests.
- Admin UI build validation.

Hardware and controller proof belongs in the release certification checklist.
