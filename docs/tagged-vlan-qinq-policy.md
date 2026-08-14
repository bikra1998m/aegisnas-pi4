# Tagged VLAN And QinQ Policy

NAS-0054 adds a vendor-neutral VLAN policy compiler for data VLANs, tagged
voice VLANs, additional tagged VLANs, VLAN pools, fallback VLANs, auth-fail
VLANs, and QinQ intent.

## Purpose

Use this feature when one local role must produce safe, repeatable VLAN
authorization across different NAS families:

- standards-based data VLAN assignment with `Tunnel-Type`,
  `Tunnel-Medium-Type`, and `Tunnel-Private-Group-Id`
- tagged VLAN assignment with RFC 4675 `Egress-VLANID`
- AegisNAS product VSAs for data, voice, tagged, QinQ, pool, fallback,
  auth-fail, and policy-mode evidence
- Extreme Switch Engine extended VLAN output
- HP/ArubaOS-Switch style tagged and untagged egress VLAN output

The compiler is deterministic. Pool assignment can be pinned to the first VLAN
or selected by hash over calling station, NAS identifier, or role.

## Configuration

```yaml
radius:
  vendor:
    compatibility_packs: ["standard", "aegisnas", "hp", "extreme"]
  vlan_policy:
    enabled: true
    fail_closed: true
    max_tagged_vlans: 10
    default_fallback_vlan: 99
    default_auth_fail_vlan: 98
    pools:
      - name: "branch-data"
        vlans: [21, 22, 23]
        strategy: "hash-calling-station"
    role_policies:
      - role: "voice-device"
        data_vlan: 21
        voice_vlan: 30
        tagged_vlans: [40, 50]
        pool: "branch-data"
        fallback_vlan: 99
        auth_fail_vlan: 98
        qinq:
          enabled: true
          outer_vlan: 3000
          inner_vlan: 21
          mode: "provider-bridge"
        vendor_packs: ["standard", "aegisnas", "hp", "extreme"]
```

Validation rejects invalid VLAN IDs, duplicate VLANs within one role policy,
unknown pools, unknown vendor packs, unsupported pool strategies, and unsafe
QinQ combinations.

## API

Inspect compiler coverage and evidence:

```text
GET /api/v1/system/vlan-policy
GET /api/v1/system/vlan-policy/history
```

Compile a role without changing live state:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"voice-device","calling_station_id":"aa:bb:cc:dd:ee:ff","nas_identifier":"branch-ap-01"}' \
  http://127.0.0.1:8083/api/v1/system/vlan-policy/compile | jq '.result'
```

Preview uses the same compiler and records evidence as a preview operation:

```text
POST /api/v1/system/vlan-policy/preview
```

Decompile observed RADIUS attributes during support or drift review:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pack_key":"aegisnas","attributes":[{"name":"AegisNAS-Data-VLAN","value":"21"},{"name":"AegisNAS-Voice-VLAN","value":"30"}]}' \
  http://127.0.0.1:8083/api/v1/system/vlan-policy/decompile | jq '.result.decision'
```

Read-only roles may inspect, preview, compile, and decompile. These operations
do not change local Linux bridges or controller state. `vlan_policy_events`
stores operation, status, role, pool, VLAN selections, QinQ selection,
attribute count, diagnostics, request/response JSON, actor, and fingerprint.

## Runtime Behavior

Generated FreeRADIUS `users` entries call the compiler for matching local
roles and MAB endpoints. When the compiler owns a reply, it suppresses duplicate
legacy simple VLAN output and renders the compiled per-pack attributes.

The NAS-0053 VLAN lifecycle uses the same configured VLAN policy as input for
local bridge, subinterface, and hostapd VLAN-file planning. That keeps RADIUS
authorization intent and local enforcement intent aligned.

## Monitoring

`/api/v1/system/status` includes `radius.vlan_policy` with status, message,
compiler version, role policy count, pool count, pool VLAN count, voice policy
count, QinQ policy count, fallback/auth-fail count, and evidence summary.

Production readiness includes the `tagged_vlan_qinq_policy` check. It verifies
compiler configuration, sample compilation, database evidence availability,
and readiness for release certification.

Support bundles include:

- `api/vlan-policy.json`
- `api/vlan-policy-history.json`

## Security

- Fail-closed mode blocks compiler output when no effective VLAN can be
  selected.
- Role policy, pool, and QinQ values are validated before config is accepted.
- The API records bounded JSON evidence and never requires shared secrets.
- Unknown inbound VLAN attributes are ignored unless they map to implemented
  semantics.
- QinQ output is emitted as AegisNAS product intent until vendor-specific
  device certification confirms native encodings for a product family.

## Engineering Completion

Software implementation is complete for NAS-0054:

- config schema and validation
- deterministic compiler and decompiler
- packet reply rendering for standard, AegisNAS, HP, and Extreme packs
- generated FreeRADIUS local-user and MAB integration
- inbound AegisNAS VSA parsing
- database evidence migration and repair
- admin API, OpenAPI, RBAC, support bundle, status, readiness
- admin UI configuration and dashboard visibility
- unit, packet, migration, API, generator, and UI build coverage

External release proof is tracked in
[NAS-0054 Release Certification Checklist](nas-0054-release-certification-checklist.md).
