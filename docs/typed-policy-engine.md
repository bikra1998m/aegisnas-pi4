# Typed Policy Expression Engine

NAS-0029 adds the typed authorization policy core used by AegisNAS to turn authentication, device, network, tenant, and posture facts into deterministic access decisions.

The engine solves the old `policy_rules.match_conditions` limitation where JSON keys were loosely interpreted and could not safely express nested conditions, CIDR checks, time windows, risk thresholds, tenant context, or explainable rule traces.

## Supported Inputs

Policy requests can include:

- identity facts: `username`, `role`, `groups`, `realm`, `tenant`
- authentication facts: `authenticated`, `auth_method`, `identity_source`
- network facts: `ssid`, `nas_identifier`, `nas_ip_address`, `nas_port_id`, `nas_port_type`, `calling_station_id`, `called_station_id`, `source_ip`, `site`, `vendor`, `vlan`
- posture facts: `device_group`, `posture`, `risk_score`
- bounded extra request values under `attributes`

Raw identifiers are not persisted in evaluation history. Usernames and calling-station IDs are hashed before storage.

## Expression Model

Typed expressions use one of four node shapes:

```json
{ "field": "groups", "op": "contains", "value": "employees" }
```

```json
{ "all": [
  { "field": "authenticated", "op": "eq", "value": true },
  { "field": "source_ip", "op": "cidr", "value": "10.0.0.0/8" }
] }
```

```json
{ "any": [
  { "field": "auth_method", "op": "eq", "value": "eap-tls" },
  { "field": "risk_score", "op": "lte", "value": 25 }
] }
```

```json
{ "not": { "field": "posture", "op": "eq", "value": "infected" } }
```

Supported operators are `eq`, `neq`, `in`, `not_in`, `contains`, `contains_any`, `prefix`, `suffix`, `regex`, `cidr`, `gt`, `gte`, `lt`, `lte`, `between`, `exists`, `time_between`, `true`, and `false`.

Legacy JSON such as `{"authenticated": true, "group": "staff"}` is compiled into the typed AST when `policy.allow_legacy_conditions` is true.

## Configuration

```yaml
policy:
  typed_engine_enabled: true
  mode: "monitor"
  fail_closed: true
  audit_enabled: true
  allow_legacy_conditions: true
  require_typed_rules: false
  max_expression_depth: 8
  max_expression_nodes: 128
  max_list_values: 128
  evaluation_retention_limit: 10000
```

Production migration path:

1. Run with `mode: monitor`, `allow_legacy_conditions: true`.
2. Convert legacy rules to typed `all`/`any`/`not` expressions.
3. Set `allow_legacy_conditions: false`.
4. Set `require_typed_rules: true`.
5. Move to `mode: enforce` after external device validation.

## APIs

- `GET /api/v1/system/policy-engine`
- `POST /api/v1/system/policy-engine/validate`
- `POST /api/v1/system/policy-engine/evaluate`

The standalone policy service also exposes:

- `POST /api/v1/evaluate`
- `POST /api/v1/evaluate-detailed`
- `GET /api/v1/catalog`

## Persistence

Schema v34 adds `policy_engine_evaluations`.

Stored evidence includes evaluation ID, policy-set hash, request hash, redacted username/calling-station hashes, decision, matched rules, conflict list, explain trace, request summary, rule counts, and latency.

## Operations

Operators should check:

- `/api/v1/system/policy-engine` before and after policy changes
- production readiness key `typed_policy_engine`
- support bundle capture `api/policy-engine.json`
- Dashboard "Typed Policy Engine"
- Policies page `Typed`, `Legacy`, and `Valid` columns

## External Certification

Automated software work is complete when tests pass and the API/UI/docs are present. Real AP/controller interop, FreeRADIUS packet-capture proof, HA drills, soak, and customer acceptance remain release certification activities tracked in `nas-0029-release-certification-checklist.md`.
