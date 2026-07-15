# RADIUS Transport Downgrade Policy

NAS-0015 adds a policy layer for outbound AAA proxy transports. It prevents a
RadSec route from silently falling back to UDP through a mixed home-server pool
unless that exception is explicit and visible.

## Feature Definition

RADIUS over UDP and RadSec both carry the same RADIUS attributes, but their
transport security is very different. A pool that contains both RadSec and UDP
home servers can accidentally downgrade sensitive traffic when a RadSec peer is
down. AegisNAS already generates `default_fallback = no`; this policy adds
route-level transport intent so mixed pools and non-RadSec routes are visible,
auditable, and enforceable.

Relevant standards:

- RFC 2865 and RFC 2866 for RADIUS authentication and accounting packet
  semantics.
- RFC 6614 for RadSec transport.
- RFC 8996, RFC 9765, and RFC 9813 where RadSec TLS policy is involved.

RadSec has no vendor dictionary or VSA. Vendor-specific attributes continue to
travel inside the selected transport unchanged.

## Configuration

The policy lives under `radius.upstream.transport_policy`:

```yaml
radius:
  upstream:
    transport_policy:
      enabled: true
      mode: enforce        # monitor or enforce
      fail_closed: true
      default_required_transport: radsec # any, radsec, or udp
      allow_mixed_transports: false
      route_policies:
        - route: guest
          required_transport: udp
          allow_mixed_transports: false
          description: "Guest route remains UDP until partner RadSec is certified."
```

Use `monitor` while migrating. Use `enforce` with `fail_closed: true` for
production sign-off. In enforce mode, FreeRADIUS proxy generation fails before
writing a configuration that violates the policy.

## Policy Rules

- `default_required_transport: any` allows pure UDP and pure RadSec routes, but
  still flags mixed UDP/RadSec pools unless `allow_mixed_transports` is true.
- `default_required_transport: radsec` requires every server on every route to
  use RadSec unless a route policy overrides it.
- `default_required_transport: udp` requires UDP and is useful only for
  explicit legacy exceptions.
- `allow_mixed_transports: false` is the downgrade guard. It blocks a route from
  failing from RadSec to UDP through the same pool.
- Route policies are named by effective proxy route name. The legacy synthesized
  route is `legacy-default`.

## API And UI

The effective report is available at:

```text
GET /api/v1/system/transport-policy
```

The same report appears in `/api/v1/system/status` as
`radius.transport_policy`. The Dashboard shows mode, default required
transport, mixed route count, violation count, and RadSec server count. Access
Settings exposes the global policy controls.

## Readiness

Production readiness includes `radius_transport_policy`.

For upstream AAA production sign-off, the check requires:

- policy enabled
- `mode: enforce`
- `fail_closed: true`
- no route transport violations

External FreeRADIUS package validation, vendor hardware, HA failover, traffic
capture, scale, soak, security, and customer acceptance remain in
`nas-0015-release-certification-checklist.md`.
