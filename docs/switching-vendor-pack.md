# NAS-0071 Enterprise Switching Vendor Pack

NAS-0071 software-certifies the FreeRADIUS 3.2.8 dictionary rows for the
enterprise switching families covered by the roadmap item: 3Com, Dell EMC,
EqualLogic, Brocade, Force10, Foundry, Arista, and Extreme.

The pack translates those vendor-specific attributes into neutral AegisNAS
semantics for role, privilege, command authorization context, VLAN and fabric
selectors, dynamic ACL/profile assignment, QoS, portal hints, session
remediation, posture, tenant, VRF, IPv4 host context, and accounting evidence.

## Supported Software Scope

- 3Com access level, VLAN name, mobility profile, encryption type, time bounds,
  SSID, end date, portal URL, connect ID, NAS startup timestamp, host IP, and
  product ID.
- Arista AVPair, user privilege, user role, CVP role, command context, WebAuth,
  block/unblock MAC, port flap, captive portal, segment ID, interface profile,
  and device profiling.
- Brocade auth role, AVPairs 1 through 4, password expiry, and warning period.
- Dell EMC AVpair and group name.
- EqualLogic admin identity, contact, poll interval, privilege, pool access,
  replication site access, and account type.
- Extreme NetLogin, CLI authorization, shell command, security profile, VM,
  VLAN, extended VLAN, portal URL, location, IP address, and virtual-router
  context.
- Force10 AVPair policy tokens.
- Foundry privilege, command, ACL, 802.1X/MAC-auth, VLAN/QoS, INM role, CoA,
  SI role, and voice phone configuration.

## API

```text
GET  /api/v1/system/switching-vendor-pack
POST /api/v1/system/switching-vendor-pack/record
GET  /api/v1/system/switching-vendor-pack/history
```

The `GET` endpoint returns the generated software certification report and
recent evidence. The `POST` endpoint records the current fingerprint in
`switching_vendor_pack_events`. The history endpoint returns durable evidence
used by readiness checks and support bundles.

## Configuration

Enable the relevant compatibility packs on a RADIUS client:

```yaml
radius:
  vendor:
    compatibility_packs:
      - standard
      - 3com
      - arista
      - brocade
      - dellemc
      - equallogic
      - force10
      - foundry
      - extreme
    role_mappings:
      - pack: arista
        role: netadmin
        value: 15
      - pack: 3com
        role: netadmin
        value: 4
      - pack: equallogic
        role: storage-admin
        value: 2
    avpair_mappings:
      - pack: arista
        role: netadmin
        values:
          - acl=${inbound_acl}
          - vrf=${tenant}
      - pack: brocade
        role: netadmin
        values:
          - acl=${inbound_acl}
          - vrf=${tenant}
      - pack: dellemc
        role: netadmin
        values:
          - role=${role}
          - acl=${acl_policy}
      - pack: force10
        role: netadmin
        values:
          - qos=${policy_tag}
```

## Packet Processing

Inbound VSAs are decoded through the generated FreeRADIUS registry and then
normalized by `internal/radius/switching_vendor.go`. Vendor AVPair grammar is
bounded to 240 bytes, rejects control characters, accepts `name=value` and
`namespace:name=value` forms, and preserves safe unknown tokens as evidence.

Outbound replies render dictionary-prefixed attributes. Numeric role mappings
are required for 3Com access levels, Arista privilege levels, and EqualLogic
admin privileges. Brocade AVPairs are distributed across `Brocade-AVPairs1`
through `Brocade-AVPairs4`.

## Operations

```bash
curl -fsS \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/switching-vendor-pack | jq '.report.summary'

curl -fsS -X POST \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/switching-vendor-pack/record | jq '.event_id, .status'

make test-switching-vendor-pack
```

## Release Boundary

Software implementation is complete when automated tests, API, UI,
configuration, packet processing, database migration, and documentation pass.
Hardware, controller, production FreeRADIUS, HA, performance, soak, security,
and customer proof are tracked in
`docs/nas-0071-release-certification-checklist.md`.
