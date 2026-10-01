# Broadband Address Lease Lifecycle

NAS-0086 adds production software support for broadband subscriber address pools and lease ownership. It binds subscriber products from `broadband.subscriber_state` to IPv4, IPv6, and delegated-prefix lease intent, records preview/apply evidence, tracks durable lease rows, and exposes operational status through the admin API, production readiness, support bundles, and the Access Settings UI.

## What It Solves

Broadband NAS and BNG deployments must keep address ownership deterministic across authentication, accounting start/interim/stop, reconnects, sticky assignments, reservations, conflict recovery, CoA/Disconnect actions, and HA replay. A product can advertise pools in RADIUS replies, but operators still need a durable server-side lifecycle so duplicate address or prefix ownership is visible before enforcement.

NAS-0086 provides that lifecycle while keeping live BRAS/BNG allocation proof as release certification.

## Vendor and Standards Coverage

The lease lifecycle is vendor neutral and maps to capabilities used by Cisco, Juniper ERX/E-Series, Huawei BRAS/BNG, Nokia/Alcatel-Lucent SR OS, MikroTik, Ericsson/Redback, H3C, ZTE, Calix, Adtran, and FreeRADIUS deployments.

Relevant RADIUS attributes and VSAs include:

- Standard IPv4: `Framed-IP-Address`, `Framed-Pool`, `Framed-Route`
- Standard IPv6: `Framed-IPv6-Address`, `Framed-IPv6-Prefix`, `Framed-IPv6-Pool`, `Delegated-IPv6-Prefix`, `Framed-IPv6-Route`, `Framed-Interface-Id`
- Accounting: `Acct-Status-Type`, `Acct-Session-Id`, `Acct-Session-Time`, `Event-Timestamp`, `Class`
- Dynamic authorization: CoA-Request, Disconnect-Request, `Error-Cause`
- Vendor families: Cisco AVPair address and prefix hints, Huawei IPv6 pool/delegation attributes, Nokia/ALU delegated-prefix semantics, MikroTik pool/address-list variants

Standards tracked by the feature:

- RFC 2865 RADIUS
- RFC 2866 RADIUS Accounting
- RFC 3162 IPv6 RADIUS attributes
- RFC 3633 IPv6 Prefix Options for DHCPv6
- RFC 4818 RADIUS delegated IPv6 prefix attributes
- RFC 5176 Dynamic Authorization
- RFC 8415 DHCPv6

## Configuration

The feature is disabled by default.

```yaml
broadband:
  address_leases:
    enabled: false
    mode: monitor
    fail_closed: true
    sticky_ipv4: true
    sticky_ipv6: true
    dual_stack_required: true
    delegated_prefix_required: true
    reservation_required: false
    conflict_detection_enabled: true
    accounting_correlation_required: true
    coa_on_conflict: true
    release_on_accounting_stop: true
    recovery_scan_seconds: 60
    stale_after_seconds: 600
    event_retention_limit: 10000
```

Explicit pools may describe pools referenced by subscriber products:

```yaml
    pools:
      - name: pppoe-v4
        family: ipv4
        cidr: 100.64.0.0/24
        start: 100.64.0.10
        end: 100.64.0.250
        product: residential-fiber
        role: residential
        dynamic: true
        sticky: true
```

Reservations bind a subscriber or username to a durable address or prefix:

```yaml
    reservations:
      - key: lab-cpe-01
        subscriber_id: sub-lab-cpe-01
        username: lab-cpe-01@example.net
        product: residential-fiber
        pool: pppoe-v4
        family: ipv4
        assignment_type: address
        address: 100.64.0.20
```

## API

- `GET /api/v1/system/broadband-address-leases`
- `POST /api/v1/system/broadband-address-leases/preview`
- `POST /api/v1/system/broadband-address-leases/apply`
- `GET /api/v1/system/broadband-address-leases/history?limit=100`

Preview records an evidence event without mutating lease rows. Apply records the event, upserts planned/reserved lease ownership rows, and updates runtime status. A blocked plan returns HTTP 409 on apply.

## Database

NAS-0086 adds schema version 88:

- `broadband_address_lease_events`
- `broadband_subscriber_address_leases`

The event table stores preview/apply/reconcile/release evidence. The lease table stores durable ownership by subscriber, session, accounting ID, product, role, family, assignment type, pool, address, prefix, reservation key, status, sticky flag, owner, revision, and source event.

## Operations

Recommended operator flow:

1. Configure `radius.address_policy`, SQL accounting, accounting services, dynamic authorization, PPPoE, and subscriber state.
2. Configure `broadband.address_leases` in monitor mode.
3. Run `POST /api/v1/system/broadband-address-leases/preview`.
4. Review blockers, warnings, pools, lease intents, reservations, and conflict policies.
5. Apply only after the preview is clean.
6. Keep live vendor allocation, packet capture, HA failover, performance, soak, and customer proof in `docs/nas-0086-release-certification-checklist.md`.

## Validation

Local software validation:

```bash
make test-broadband-address-leases
```

The target runs config, enforcement, DB migration, admin API, and admin UI build checks.
