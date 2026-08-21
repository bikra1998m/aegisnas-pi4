# IPv4 / IPv6 Pools, DHCPv6, RA, And Prefix Delegation

NAS-0056 adds a vendor-neutral address policy compiler for dual-stack access,
subscriber, VPN, and BNG sessions. It turns role intent into standard RADIUS
attributes, AegisNAS product VSAs, and selected vendor-specific attributes.

## Purpose

Use this feature when a role must assign or advertise address resources through
RADIUS:

- IPv4 framed address, netmask, and pool assignment
- IPv6 framed address, framed prefix, and pool assignment
- DHCPv6 prefix delegation
- router advertisement on-link prefix metadata
- DHCPv6 and RA mode hints for controller or NAS adapters
- owner, revision, and lifecycle evidence for active and withdrawn assignments

The software path is complete for compilation, decompilation, reply rendering,
configuration validation, API exposure, UI editing, database evidence, and
Accounting Stop withdrawal. Native DHCPv6 daemon behavior, router advertisement
packet emission, and exact device enforcement remain release certification work
for each supported product and firmware.

## Standards And Dictionaries

The software path is based on:

- RFC 2865 `Framed-IP-Address`, `Framed-IP-Netmask`, and `Framed-Pool`
- RFC 3162 `Framed-IPv6-Address`, `Framed-IPv6-Prefix`, and
  `Framed-IPv6-Pool`
- RFC 6911 `Delegated-IPv6-Prefix`
- RFC 3315 / RFC 8415 DHCPv6 lifecycle semantics
- RFC 3633 IPv6 prefix delegation
- RFC 4861 / RFC 4862 router advertisements and SLAAC
- RFC 5176 CoA/Disconnect lifecycle integration

Vendor dictionaries involved include standards-based RADIUS, AegisNAS, Cisco,
Juniper / ERX, Huawei, H3C, MikroTik, Nokia / Alcatel-Lucent service-router
families, and other BNG or NAS devices that consume framed address and delegated
prefix attributes.

## Attributes

Standard attributes:

- `Framed-IP-Address`
- `Framed-IP-Netmask`
- `Framed-Pool`
- `Framed-IPv6-Address`
- `Framed-IPv6-Prefix`
- `Framed-IPv6-Pool`
- `Delegated-IPv6-Prefix`

AegisNAS product VSAs:

- `AegisNAS-Address-Policy`
- `AegisNAS-Address-Owner`
- `AegisNAS-Address-Revision`
- `AegisNAS-IPv4-Pool`
- `AegisNAS-IPv6-Pool`
- `AegisNAS-Delegated-IPv6-Pool`
- `AegisNAS-RA-Prefix-Pool`
- `AegisNAS-Framed-IP-Address`
- `AegisNAS-Framed-IPv6-Address`
- `AegisNAS-Framed-IPv6-Prefix`
- `AegisNAS-Delegated-IPv6-Prefix`
- `AegisNAS-RA-Prefix`
- `AegisNAS-DHCPv6-Mode`
- `AegisNAS-RA-Mode`

Vendor-specific output includes Cisco, Juniper, Huawei, H3C, Nokia AVPair-style
address metadata, Juniper `Juniper-Ip-Pool-Name`, Huawei
`Huawei-Framed-Pool`, `Huawei-Framed-IPv6-Address`,
`Huawei-Delegated-IPv6-Prefix-Pool`, and MikroTik
`Mikrotik-Delegated-IPv6-Pool`.

## Configuration

```yaml
radius:
  vendor:
    compatibility_packs: ["standard", "aegisnas", "cisco", "juniper", "huawei", "mikrotik", "nokia"]
  address_policy:
    enabled: true
    fail_closed: false
    max_assignments: 128
    default_owner: "aegisnas"
    conflict_mode: "block"
    stop_withdrawal: true
    dhcpv6:
      enabled: true
      managed_address: true
      other_config: true
      prefix_delegation: true
      default_t1_seconds: 1800
      default_t2_seconds: 2880
      valid_lifetime_seconds: 86400
      preferred_lifetime_seconds: 43200
      dns_servers: ["2001:4860:4860::8888"]
      domain_search: ["corp.example"]
    ra:
      enabled: true
      managed_flag: false
      other_config_flag: true
      default_router_preference: "medium"
      valid_lifetime_seconds: 86400
      preferred_lifetime_seconds: 43200
      rdnss: ["2001:4860:4860::8888"]
      dnssl: ["corp.example"]
    pools:
      - name: "branch-v4"
        family: "ipv4"
        cidr: "198.51.100.0/24"
        start: "198.51.100.10"
        end: "198.51.100.200"
        gateway: "198.51.100.1"
        mode: "address"
      - name: "branch-v6"
        family: "ipv6"
        cidr: "2001:db8:10::/120"
        mode: "address"
      - name: "branch-pd"
        family: "ipv6"
        cidr: "2001:db8:100::/48"
        delegated_prefix_length: 56
        mode: "delegated-prefix"
      - name: "branch-ra"
        family: "ipv6"
        cidr: "2001:db8:200::/56"
        prefix_length: 64
        mode: "ra-prefix"
    role_policies:
      - role: "branch-dualstack"
        owner: "network-team"
        ipv4_pool: "branch-v4"
        ipv6_pool: "branch-v6"
        delegated_ipv6_pool: "branch-pd"
        ra_prefix_pool: "branch-ra"
        dhcpv6_mode: "stateful-pd"
        ra_mode: "slaac"
        vendor_packs: ["standard", "aegisnas", "cisco"]
```

Validation rejects invalid pool CIDRs, family mismatches, duplicate or
overlapping pools, start/end ranges outside the pool, gateway-family mismatch,
invalid DNS or domain values, invalid prefix lengths, unknown pool references,
unsafe owner text, unknown vendor packs, unsupported DHCPv6 or RA modes, and
excessive assignment counts.

Conflict modes:

- `block`: conflicting request and role assignments block compilation.
- `prefer-role`: role policy wins and request-provided values are ignored.
- `prefer-request`: request values override role policy values.
- `warn`: both sources are accepted and the result is degraded.

## API

Inspect compiler coverage and evidence:

```text
GET /api/v1/system/address-policy
GET /api/v1/system/address-policy/history
```

Preview without changing ownership:

```text
POST /api/v1/system/address-policy/preview
```

Compile address attributes and update the address ownership ledger:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"branch-dualstack","session_id":"session-1","acct_session_id":"acct-1","pack_keys":["standard","aegisnas","cisco"]}' \
  http://127.0.0.1:8083/api/v1/system/address-policy/compile | jq '.result.attributes'
```

Decompile observed packet attributes without changing ownership:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pack_key":"aegisnas","role":"branch-dualstack","attributes":[{"name":"AegisNAS-IPv4-Pool","value":"branch-v4"},{"name":"AegisNAS-Framed-IP-Address","value":"198.51.100.42"},{"name":"AegisNAS-Delegated-IPv6-Prefix","value":"2001:db8:100:4200::/56"}]}' \
  http://127.0.0.1:8083/api/v1/system/address-policy/decompile | jq '.result.decision'
```

Read-only roles may inspect, preview, and decompile. `ops_admin` and
`super_admin` may compile because compile updates the software ownership
ledger.

## Runtime Behavior

Generated FreeRADIUS local-user and MAB replies call the compiler for matching
roles. When a matching address policy exists, the reply renderer adds standard,
AegisNAS, and configured vendor-pack address attributes.

Pool selections are deterministic for the session, accounting session, calling
station, NAS identifier, and role so HA peers can reproduce the same compiled
intent from shared config and evidence. Compile creates active ownership rows
for concrete IPv4 addresses, IPv6 addresses, delegated prefixes, and RA
prefixes. Accounting Stop and Accounting-Off withdraw active rows for the
matching session or accounting session ID when `stop_withdrawal` is enabled.

Preview and decompile create immutable evidence events only.

## Database

Schema v61 adds:

- `address_policy_events`
- `address_policy_ownership`

Events store operation, status, role, session, accounting session, owner,
revision, assignment counts, attribute counts, diagnostics, request JSON,
response JSON, actor, and fingerprint. Ownership rows store deterministic
ownership keys, concrete address or prefix assignments, pool names, active or
withdrawn status, and timestamps.

## Monitoring

`/api/v1/system/status` includes `radius.address_policy` with compiler status,
configured policy counts, pool counts, active assignments, withdrawn
assignments, delegated-prefix counts, RA-prefix counts, last event status, and
last role.

Production readiness includes the `ipv4_ipv6_pool_dhcpv6_ra_pd` check. It
verifies that the compiler is enabled, sample compilation works, evidence
tables are available, and the address ownership ledger is queryable.

Support bundles include:

- `api/address-policy.json`
- `api/address-policy-history.json`

## High Availability

Address policy state is configuration and database backed. HA nodes must
replicate schema v61, `address_policy_events`, and `address_policy_ownership`
before failover claims are made. Ownership keys are deterministic for the
session, owner, family, pool, address, and prefix so a standby can continue
evidence correlation after failover.

## Security

- API access is RBAC controlled.
- Compile is restricted to `ops_admin` and `super_admin`.
- Pool, address, prefix, owner, and vendor-pack values are validated before use.
- Evidence records are bounded by API limits and support bundle redaction rules.
- Native DHCPv6/RA enforcement must use least-privilege adapters and separate
  release certification before production claims are made.

## Release Certification Boundary

Software implementation is complete when code, migrations, APIs, UI, tests,
documentation, and CI pass. Release sign-off still requires production Linux
FreeRADIUS packet captures, target vendor hardware or controller smoke tests,
DHCPv6/RA daemon validation, HA failover proof, performance benchmarks, soak
tests, security review, and customer acceptance evidence.
