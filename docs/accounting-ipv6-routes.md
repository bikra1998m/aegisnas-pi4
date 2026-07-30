# NAS-0038 IPv6, Prefix, And Route Accounting

NAS-0038 makes accounting records useful for dual-stack enterprise networks,
BNG/BRAS deployments, and routed subscriber sessions. It records the IP address,
IPv6 prefix, delegated prefix, interface identifier, and framed route attributes
sent by access devices, then mirrors the current assignment state into sessions
and FreeRADIUS-compatible SQL rows.

## Problem

Large NAS and AAA deployments need more than a username and byte counter. They
need to know which IPv4 address, IPv6 address, delegated prefix, and static route
were assigned to a session at a specific time. Without this evidence, operators
cannot reliably investigate abuse reports, subscriber route ownership, dual-stack
access failures, or BNG accounting disputes.

## Supported Attributes

- `Framed-IP-Address`
- `Framed-IPv6-Address`
- `Framed-IPv6-Prefix`
- `Framed-Interface-Id`
- `Delegated-IPv6-Prefix`
- `Framed-Route`
- `Framed-IPv6-Route`

The feature is standards-based and maps to surfaces used by Cisco, Juniper ERX,
Huawei, Nokia, broadband BNG/BRAS platforms, 3GPP packet-core integrations, and
other vendors that expose IPv6 and route state through FreeRADIUS dictionaries.

## Runtime Behavior

- Local accounting events canonicalize IPv4 addresses, IPv6 addresses, IPv6
  prefixes, delegated prefixes, and framed route destinations before storage.
- FreeRADIUS SQL `radacct` imports are normalized through the same path during
  reconciliation.
- `sessions` stores current `ipv6_address`, `framed_ipv6_prefix`,
  `delegated_ipv6_prefix`, `framed_interface_id`, `framed_route`, and
  `framed_ipv6_route` values.
- `radacct` stores `framedroute`, `framedipv6route`, `aegis_route_status`,
  `aegis_route_error`, and `aegis_last_route_event_id`.
- `radius_accounting_events` stores normalized route/prefix fields plus
  `ip_assignment_status` and `ip_assignment_error`.
- `radius_accounting_ip_assignments` stores durable assignment evidence with
  active, closed, and invalid validation state.
- Stop and Accounting-Off events close active assignment rows for the session.

## Configuration

```yaml
radius:
  accounting_ip:
    enabled: true
    ipv6_enabled: true
    route_accounting_enabled: true
    delegated_prefix_enabled: true
    reject_invalid: false
    retention_days: 365
```

Production readiness blocks when accounting IP tracking is disabled or when
IPv6, route, or delegated-prefix families are disabled. Invalid assignment rows
degrade readiness and should be resolved before production claims.

## API And Evidence

```text
GET /api/v1/system/accounting-ip
GET /api/v1/system/accounting-ip?validation_status=invalid&limit=100
GET /api/v1/system/accounting-ip?session_key=sess-1&limit=100
```

The response includes the effective policy, supported attributes, RFCs, vendor
scope, assignment counts, active/closed counts, IPv6 address and prefix counts,
delegated prefix counts, route counts, invalid evidence, recent assignment rows,
and warnings. The same report appears in:

- `/api/v1/system/status` as `radius.accounting_ip`
- production readiness as `radius_accounting_ip`
- support bundles as `api/accounting-ip.json`
- Access Settings and Dashboard accounting panels

## Operations

Before production sign-off:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-ip | jq '.report.status, .report.summary'
```

After importing FreeRADIUS SQL rows, replaying accounting events, or running
dual-stack access tests, confirm:

- `status` is `ready`
- `invalid_rows` is `0`
- expected IPv6 sessions appear in `ipv6_address_rows` or `ipv6_prefix_rows`
- expected routed or BNG sessions appear in `delegated_prefix_rows`,
  `ipv4_route_rows`, or `ipv6_route_rows`
- Stop or Accounting-Off tests close active assignments

## Release Boundary

Software implementation is complete when the schema, packet/SQL normalization,
API, UI, readiness checks, support bundle evidence, tests, docs, and CI target
pass. Real vendor packet captures, production Linux FreeRADIUS imports, HA
failover drills, performance benchmarks, long-duration soak tests, and customer
validation are tracked in `nas-0038-release-certification-checklist.md`.
