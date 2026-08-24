# NAS-0061 Cisco Family Pack

NAS-0061 closes the software engineering gap for Cisco-family dictionaries in
the pinned FreeRADIUS 3.2.8 VSA audit.

The covered vendors are Cisco, Airespace, Cisco-ASA, Cisco-BBSM,
Cisco-VPN3000, Cisco-VPN5000, Starent, and Meraki. The report covers all 922
rows from the pinned registry for those vendors.

## Software Scope

The Cisco-family pack provides:

- typed registry coverage for all 922 Cisco-family dictionary rows
- Cisco-AVPair parser, classifier, and compiler support
- inbound normalization for known Cisco-AVPair semantics
- outbound Cisco-AVPair rendering for TrustSec SGT, VPN policy, voice traffic
  class, command authorization, posture, charging, and custom safe AVPairs
- native semantic coverage for existing Cisco, Airespace, Meraki, and Starent
  mappings
- governed typed pass-through for dictionary-known rows without a neutral
  behavior contract
- durable certification events in `cisco_family_pack_events`
- admin API, Vendor Compatibility UI, production readiness, system status, and
  support-bundle visibility

Typed pass-through means AegisNAS safely identifies, bounds, stores, and
reports the attribute without claiming device-side behavior. Real hardware and
firmware acceptance remains release certification.

## Cisco-AVPair Grammar

The software parser/compiler recognizes:

- `ip:inacl#N=<rule>` and `ip:outacl#N=<rule>` downloadable ACL rules
- `cts:security-group-tag=<sgt>` and TrustSec group labels
- `vpn:*`, `webvpn:*`, and `ipsec:*` policy selectors
- `device-traffic-class=voice` voice traffic hints
- `shell:priv-lvl=<level>` and `shell:roles=<roles>` command authorization
- `posture:status=<state>` and `audit-session-id=<id>` posture/session context
- `ip:route=<route>` and `ipv6:route=<route>` route hints
- `ip:vrf-id=<vrf>` VRF selection
- `ip:addr-pool=<pool>`, `ipv6:addr-pool=<pool>`, and delegated-prefix hints
- `translation-*` CGNAT/NAT64 policy hints
- `subscriber:charging-profile=<profile>` charging policy hints

Unknown but syntactically safe AVPairs are preserved as bounded raw evidence.
Unsafe values with control characters, invalid tokens, empty values, or values
over the configured maximum are rejected by the parser.

## API

```text
GET  /api/v1/system/cisco-family-pack
POST /api/v1/system/cisco-family-pack/record
GET  /api/v1/system/cisco-family-pack/history
```

`GET` returns the derived report, grammar evidence, vendor rollups, capability
rollups, sample records, release scope, and recent persisted events. `POST`
records the current source hash, fingerprint, counts, summary JSON, full report
JSON, actor, and timestamp. `history` returns event summary and recent rows.

## Database

Schema v66 adds:

```text
cisco_family_pack_events
```

Each event stores release profile ID, registry source hash, attribute counts,
native mapping count, typed pass-through count, grammar rule count, software
certified count, blocker count, external-required count, vendor count,
fingerprint, summary JSON, full report JSON, actor, and creation time.

The current certification truth is re-derived from the pinned registry and code
on every request. History records are evidence snapshots, not mutable source of
truth.

## Operations

Inspect current software readiness:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/cisco-family-pack | jq '.report.summary'
```

Record the current evidence snapshot after tests pass:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/cisco-family-pack/record | jq '.event_id, .status'
```

Production readiness includes `cisco_family_pack`. System status includes
`radius.cisco_family_pack`. Support bundles include:

- `api/cisco-family-pack.json`
- `api/cisco-family-pack-history.json`

## External Release Boundary

The 922 rows are software-certified and ready for external validation. Complete
[nas-0061-release-certification-checklist.md](nas-0061-release-certification-checklist.md)
before publishing hardware-certified Cisco, WLC, ASA/VPN, Starent, Meraki, HA,
performance, security, or customer-environment claims.

## Automated Tests

```bash
make test-cisco-family-pack
```

The target covers the Cisco-family report, Cisco-AVPair parser/compiler,
inbound normalization, reply rendering, schema migration, event ledger, admin
APIs, RBAC, OpenAPI, production readiness, support-bundle capture registration,
and the Vendor Compatibility UI build.
