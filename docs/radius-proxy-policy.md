# RADIUS Proxy Loop And Attribute Policy

NAS-0011 adds route-scoped proxy loop prevention and attribute policy for
upstream AAA. It builds on the NAS-0010 route table and keeps policy decisions
explicit per proxy route.

## What It Solves

RADIUS proxy deployments can fail dangerously when traffic loops between
proxies, when a realm accepts traffic from an unexpected source realm, or when
vendor attributes cross a trust boundary without review. NAS-0011 provides:

- a bounded loop marker added to generated proxy traffic
- rejection when the marker returns on a later hop
- per-route trusted source realms
- per-route standard attribute allow/deny policy
- per-route vendor ID and vendor attribute selectors
- safe `User-Name` realm rewrite rules
- API, dashboard, readiness, and FreeRADIUS generation evidence

## Configuration

Proxy policy lives under `radius.upstream.proxy_policy`:

```yaml
radius:
  upstream:
    proxy_policy:
      enabled: true
      fail_closed: true
      default_action: drop
      loop_marker: aegisnas
      add_loop_marker: true
      reject_loop_marker: true
      max_hops: 8
      route_policies:
        - route: corp
          direction: any
          trusted_source_realms:
            - corp.example.com
            - employees.example.com
          allow_standard:
            - User-Name
            - EAP-Message
            - Message-Authenticator
          allow_vendor_ids:
            - 9
            - 14823
          deny_standard:
            - Filter-Id
          rewrite_rules:
            - attribute: User-Name
              action: replace_realm
              match_realm: employees.example.com
              replacement: corp.example.com
```

Policy fields:

- `enabled`: controls route policy enforcement and generated FreeRADIUS policy.
- `fail_closed`: rejects packets that cannot be matched to a route policy.
- `default_action`: `drop` unknown attributes or `reject` the packet.
- `loop_marker`: marker used in `Proxy-State` loop detection.
- `add_loop_marker`: adds an AegisNAS `Proxy-State` marker before proxying.
- `reject_loop_marker`: rejects packets that already contain the marker.
- `max_hops`: maximum accepted `Proxy-State` hop count.
- `route_policies`: route-specific trust, selector, and rewrite rules.

If no explicit route policy exists, AegisNAS synthesizes an implicit policy for
each enabled route. The implicit policy allows standards-required authentication
and accounting attributes and trusts the route's configured match realms.

## FreeRADIUS Generation

AegisNAS generates `pre-proxy` and `post-proxy` sections in both
`sites-enabled/default` and `sites-enabled/inner-tunnel`.

Generated policy includes:

- loop-marker rejection
- route-scoped `Proxy-State` marker insertion
- route trusted-source realm checks
- route standard-attribute deny rules
- `User-Name` rewrite rules

Vendor-specific allow/deny selectors are enforced by the AegisNAS policy
evaluator and reported through the API. Real-device certification must validate
the exact FreeRADIUS and vendor behavior before release sign-off.

## API And Readiness

Use:

```text
GET /api/v1/system/proxy-policy
```

Production readiness includes `radius_proxy_policy`.

## Standards

- RFC 2865 RADIUS and `Proxy-State`
- RFC 2866 Accounting proxy workflows
- RFC 2869 EAP-related RADIUS attributes
- RFC 5176 dynamic authorization paths that later depend on reverse proxy
  routing

## Release Certification Checklist

External lab evidence is tracked in
`nas-0011-release-certification-checklist.md`.
