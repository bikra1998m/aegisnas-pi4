# CGNAT, NAT64, And Deterministic Subscriber Translation

NAS-0057 adds a vendor-neutral translation policy compiler for ISP, BNG, branch,
and enterprise subscriber sessions. It turns role intent into AegisNAS product
VSAs and selected vendor-specific attributes for public IPv4 assignment, NAT64
prefix hints, deterministic port blocks, and accounting/logging correlation.

## Purpose

Use this feature when a role must carry subscriber translation intent through
RADIUS:

- deterministic CGNAT or NAT44 public IPv4 mapping
- NAT64 prefix intent for IPv6-only or dual-stack subscribers
- deterministic TCP/UDP port block selection
- private IPv4 and subscriber IPv6 prefix correlation
- logging profile and accounting key generation for audit trails
- owner, revision, fingerprint, and active/withdrawn ownership evidence

The software path is complete for compilation, decompilation, reply rendering,
configuration validation, API exposure, UI editing, database evidence,
production readiness, support bundles, and Accounting Stop withdrawal. Native
dataplane installation, legal-retention policy approval, and exact device
behavior remain release certification work for each supported product and
firmware.

## Standards And Dictionaries

The software path is based on:

- RFC 2865 RADIUS authorization attributes and Vendor-Specific Attributes
- RFC 5176 CoA/Disconnect lifecycle integration
- RFC 6052 IPv6 address embedding prefix rules
- RFC 6146 NAT64 behavior
- RFC 6888 carrier-grade NAT requirements

Vendor dictionaries involved include AegisNAS, Cisco, Juniper / ERX, Huawei,
H3C, Nokia / Alcatel-Lucent, Starent / Cisco ASR mobile core, Ruckus, and other
BNG or NAS families that consume AVPair-style translation hints or pool
selectors.

## Attributes

AegisNAS product VSAs:

- `AegisNAS-Translation-Policy`
- `AegisNAS-Translation-Owner`
- `AegisNAS-Translation-Revision`
- `AegisNAS-Translation-Mode`
- `AegisNAS-Translation-Public-IPv4-Pool`
- `AegisNAS-Translation-Public-IPv4-Address`
- `AegisNAS-Translation-Private-IPv4-Prefix`
- `AegisNAS-Translation-Subscriber-IPv6-Prefix`
- `AegisNAS-Translation-NAT64-Prefix`
- `AegisNAS-Translation-Port-Block-Start`
- `AegisNAS-Translation-Port-Block-End`
- `AegisNAS-Translation-Port-Block-Size`
- `AegisNAS-Translation-Logging-Profile`
- `AegisNAS-Translation-Accounting-Key`

Vendor-specific output includes Cisco `Cisco-AVPair`, Juniper
`Juniper-AV-Pair`, Huawei `Huawei-AVpair`, H3C `H3C-Av-Pair` and
`H3C-NAT-IP-Address`, Nokia `Nokia-AVPair`, Starent `SN-NAT-IP-Address` and
`SN-IP-Pool-Name`, ERX `ERX-Address-Pool-Name`, and Ruckus
`Ruckus-Nat-Pool-Name`.

## Configuration

```yaml
radius:
  vendor:
    compatibility_packs: ["aegisnas", "cisco", "juniper", "huawei", "h3c", "nokia", "starent", "erx"]
  translation_policy:
    enabled: true
    fail_closed: false
    max_mappings: 256
    default_owner: "aegisnas"
    conflict_mode: "block"
    stop_withdrawal: true
    allocation_mode: "deterministic"
    default_port_block_size: 512
    min_port: 1024
    max_port: 65535
    default_nat64_prefix: "64:ff9b::/96"
    logging_required: true
    accounting_correlation: true
    pools:
      - name: "cgnat-public"
        family: "ipv4"
        cidr: "198.51.100.0/24"
        start: "198.51.100.10"
        end: "198.51.100.250"
        port_start: 1024
        port_end: 65535
        port_block_size: 512
        mode: "cgnat"
    role_policies:
      - role: "branch-dualstack"
        owner: "nat-team"
        translation_mode: "dual-stack"
        public_pool: "cgnat-public"
        private_ipv4_prefix: "100.64.0.0/10"
        subscriber_ipv6_prefix: "2001:db8:57::/64"
        nat64_prefix: "64:ff9b::/96"
        port_block_size: 512
        logging_profile: "lawful-cgnat"
        accounting_correlation: true
        vendor_packs: ["aegisnas", "cisco", "juniper", "huawei", "h3c", "nokia", "starent", "erx"]
```

## API

```text
GET  /api/v1/system/translation-policy
POST /api/v1/system/translation-policy/preview
POST /api/v1/system/translation-policy/compile
POST /api/v1/system/translation-policy/decompile
GET  /api/v1/system/translation-policy/history
```

Read-only roles may inspect, preview, and decompile. `ops_admin` and
`super_admin` may compile because compile records active or withdrawn
translation ownership.

Example:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"role":"branch-dualstack","session_id":"session-1","acct_session_id":"acct-1","calling_station_id":"aa:bb:cc:dd:ee:ff","pack_keys":["aegisnas","cisco","juniper","huawei","h3c","nokia","starent","erx"]}' \
  http://127.0.0.1:8083/api/v1/system/translation-policy/compile | jq '.result.attributes'
```

Preview and decompile are evidence-only. They do not update active translation
ownership. Compile updates `translation_policy_ownership`, and Accounting Stop
or Accounting-Off withdraws matching active ownership rows when
`stop_withdrawal` is enabled.

## Operational Evidence

Software evidence is stored in:

- `translation_policy_events`
- `translation_policy_ownership`

System status exposes the summary as `radius.translation_policy`. Production
readiness checks the feature as `cgnat_nat64_deterministic_translation`.
Support bundles include:

- `api/translation-policy.json`
- `api/translation-policy-history.json`

## Security And HA

- Config validation rejects invalid NAT64 prefixes, non-IPv4 public pools,
  overlapping public pools, invalid port ranges, unknown vendor packs, and role
  conflicts.
- Compile results include owner, revision, ownership key, accounting key, and
  SHA-256 fingerprint.
- Accounting Stop and Accounting-Off withdraw active software ownership by
  session ID or accounting session ID.
- HA validation for active ownership replication and dataplane convergence is
  tracked in the NAS-0057 release certification checklist.
