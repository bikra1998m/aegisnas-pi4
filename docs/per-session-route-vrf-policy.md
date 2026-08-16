# Per-Session Route And VRF Policy

NAS-0055 adds a vendor-neutral compiler for per-session static route
authorization, IPv6 framed routes, VRF context, and route ownership evidence.

## Purpose

Use this feature when a role must inject deterministic routed subscriber,
VPN, branch, wholesale, or BNG service routes through RADIUS:

- standards-based IPv4 route assignment with `Framed-Route`
- standards-based IPv6 route assignment with `Framed-IPv6-Route`
- AegisNAS product VSAs for policy mode, VRF, owner, revision, and framed route
  evidence
- Cisco `Cisco-AVPair` route and VRF strings
- Juniper, Huawei, H3C, and Nokia AVPair route and VRF strings
- durable ownership evidence for active and withdrawn route assignments

This closes the software gap between NAS-0038 accounting route visibility and
authorization-time route intent. External device behavior, kernel route
installation, controller route publication, and hardware packet captures remain
release certification work.

## Standards And Dictionaries

The software path is based on:

- RFC 2865 `Framed-Route`
- RFC 3162 `Framed-IPv6-Route`
- RFC 5176 CoA/Disconnect lifecycle integration

Vendor dictionaries involved include Cisco, Juniper/ERX, Huawei, H3C, Nokia /
Alcatel-Lucent service-router families, MikroTik and standards-based NAS
devices that consume `Framed-Route` or `Framed-IPv6-Route`.

## Configuration

```yaml
radius:
  vendor:
    compatibility_packs: ["standard", "aegisnas", "cisco", "juniper", "huawei", "nokia"]
  route_policy:
    enabled: true
    fail_closed: false
    max_routes: 32
    default_vrf: "default"
    default_owner: "aegisnas"
    conflict_mode: "block"
    stop_withdrawal: true
    vrfs:
      - name: "corp"
        route_distinguisher: "65000:10"
    role_policies:
      - role: "branch-vpn"
        vrf: "corp"
        owner: "network-team"
        ipv4_routes:
          - destination: "10.80.0.0/16"
            gateway: "192.0.2.1"
            metric: 10
            interface: "pppoe0"
            tag: "branch"
        ipv6_routes:
          - destination: "2001:db8:80::/48"
            gateway: "2001:db8::1"
            metric: 20
        vendor_packs: ["standard", "aegisnas", "cisco"]
```

Validation rejects invalid prefixes, gateway-family mismatches, duplicate route
destinations within one role policy, unknown VRFs, unsafe owner/VRF text,
unknown vendor packs, excessive route counts, and unsupported conflict modes.

Conflict modes:

- `block`: conflicting request and role routes block compilation.
- `prefer-role`: role policy wins and the request route is ignored.
- `prefer-request`: request route replaces role route metadata.
- `warn`: both routes are kept and the result is degraded.

## API

Inspect compiler coverage and evidence:

```text
GET /api/v1/system/route-policy
GET /api/v1/system/route-policy/history
```

Preview without changing ownership:

```text
POST /api/v1/system/route-policy/preview
```

Compile route/VRF attributes and update the route ownership ledger:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"branch-vpn","session_id":"session-1","acct_session_id":"acct-1","pack_keys":["standard","aegisnas","cisco"]}' \
  http://127.0.0.1:8083/api/v1/system/route-policy/compile | jq '.result.attributes'
```

Decompile observed packet attributes without changing ownership:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pack_key":"aegisnas","attributes":[{"name":"AegisNAS-VRF","value":"corp"},{"name":"AegisNAS-Framed-Route","value":"10.80.0.0/16 192.0.2.1 10"}]}' \
  http://127.0.0.1:8083/api/v1/system/route-policy/decompile | jq '.result.decision'
```

Read-only roles may inspect, preview, and decompile. `ops_admin` and
`super_admin` may compile because compile updates the software ownership
ledger.

## Runtime Behavior

Generated FreeRADIUS local-user and MAB replies call the compiler for matching
roles. When a matching route policy exists, the reply renderer adds standard,
AegisNAS, and configured vendor-pack route/VRF attributes.

Preview and decompile create immutable evidence events only. Compile creates
evidence and active route ownership rows in `route_policy_ownership`.
Accounting Stop and Accounting-Off records withdraw active ownership rows for
the matching session or accounting session ID.

## Monitoring

`/api/v1/system/status` includes `radius.route_policy` with compiler status,
configured policy counts, route counts, active route ownership, withdrawn route
ownership, last event status, last role, and last VRF.

Production readiness includes the `per_session_route_vrf_policy` check. It
verifies that the compiler is enabled, sample compilation works, evidence tables are
available, and the route ownership ledger is queryable.

Support bundles include:

- `api/route-policy.json`
- `api/route-policy-history.json`

## High Availability

Route policy state is database-backed. HA nodes must replicate schema v60,
`route_policy_events`, and `route_policy_ownership` before failover claims are
made. Route ownership keys are deterministic for the session, VRF, owner,
family, and destination so a standby can continue evidence correlation after
failover.

## Release Certification Checklist

Software implementation is complete when code, migrations, APIs, UI, tests,
documentation, and CI pass. Release sign-off still requires:

- FreeRADIUS packet captures on production Linux
- Cisco, Juniper, Huawei, H3C, Nokia, MikroTik, and standards-based device
  smoke tests for `Framed-Route`, `Framed-IPv6-Route`, and AVPair behavior
- CoA route update and Accounting Stop withdrawal drills
- HA failover evidence with active route ownership
- performance, soak, security, and customer acceptance evidence
