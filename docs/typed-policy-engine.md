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
  max_service_chain_length: 16
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

Schema v34 adds `policy_engine_evaluations`. Schema v36 adds
`request_replay_json` to retained evaluations so candidate policy versions can
be replayed without storing usernames or supplicant MAC addresses.
Schema v37 adds `policy_rules.service_chain_json`, service-chain delta
tracking in policy simulation analyses, and subscriber service-chain evidence
tables.

Schema v38 adds TACACS+ command authorization and device-admin accounting
evidence tables.

Stored evidence includes evaluation ID, policy-set hash, request hash, redacted username/calling-station hashes, decision, matched rules, conflict list, explain trace, request summary, replay-safe request facts, rule counts, and latency.

Policy decisions can include `service_chain`, an ordered list of service
intents with dependencies and optional service-level attributes. Use this for
BNG, broadband, WLAN, and controller workflows that need several authorized
services on one subscriber session. See
[subscriber-service-chains.md](subscriber-service-chains.md).

## Operations

Operators should check:

- `/api/v1/system/policy-engine` before and after policy changes
- `/api/v1/system/policy-sets` for immutable versions, approvals, activation, simulation, and rollback evidence
- `/api/v1/system/policy-sets/versions/{id}/analyze` before activation
- `/api/v1/system/policy-sets/analyses` for retained blast-radius evidence
- `/api/v1/system/subscriber-service-chains` for service activation, rollback, and accounting evidence
- `/api/v1/system/tacacs` for TACACS+ command authorization, privilege, and accounting evidence
- production readiness key `typed_policy_engine`
- production readiness key `subscriber_service_chains`
- production readiness key `tacacs_command_authorization`
- support bundle capture `api/policy-engine.json`
- support bundle capture `api/subscriber-service-chains.json`
- support bundle capture `api/tacacs.json`
- Dashboard "Typed Policy Engine"
- Policies page `Typed`, `Legacy`, and `Valid` columns

For governed production changes, use [versioned-policy-sets.md](versioned-policy-sets.md). The typed engine prefers the active immutable policy-set version when one exists, while activation mirrors flattened rules back into `policy_rules` for backward compatibility.

## External Certification

Automated software work is complete when tests pass and the API/UI/docs are present. Real AP/controller interop, FreeRADIUS packet-capture proof, HA drills, soak, and customer acceptance remain release certification activities tracked in `nas-0029-release-certification-checklist.md`.
