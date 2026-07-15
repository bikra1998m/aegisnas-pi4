# RADIUS Proxy Routing

NAS-0010 adds a config-backed multi-realm proxy route table for upstream AAA.
It replaces the previous single generated realm/pool behavior while preserving
the old `radius.upstream.realm` settings as a synthesized default route when no
explicit route table is configured.

## What It Solves

Enterprise and roaming deployments often need different upstream AAA paths for
different realms:

- corporate 802.1X users to the enterprise IdP or NPS/FreeRADIUS pair
- guest or contractor identities to a delegated service
- eduroam or partner realms to a federation proxy
- branch traffic to a local pool with fail-over to a central pool

FreeRADIUS represents this with `home_server`, `home_server_pool`, and `realm`
blocks in `proxy.conf`. AegisNAS now generates those blocks from one validated
route table and exposes the effective state through the admin API.

## Configuration

Routes live under `radius.upstream.routes`:

```yaml
radius:
  upstream:
    enabled: true
    pool_strategy: fail-over
    status_check: status-server
    servers:
      - name: primary-aaa
        address: 10.10.10.10
        secret_ref: env:AEGIS_SECRET_UPSTREAM_PRIMARY
      - name: secondary-aaa
        address: 10.10.10.11
        secret_ref: env:AEGIS_SECRET_UPSTREAM_SECONDARY
    routes:
      - name: corp
        enabled: true
        realm: corp.example.com
        match_realms: [employees.example.com]
        default: true
        strip_realm: false
        pool_strategy: fail-over
        status_check: status-server
        servers: [primary-aaa, secondary-aaa]
      - name: guest
        enabled: true
        realm: guest.example.com
        default: false
        pool_strategy: load-balance
        servers: [secondary-aaa]
```

Route fields:

- `name`: stable route identifier. Used to derive generated pool names.
- `realm`: canonical FreeRADIUS realm and primary suffix match.
- `match_realms`: optional aliases that map to the same pool.
- `default`: emits `DEFAULT` and `NULL` realms and lets the site policy proxy
  unmatched or realm-less users to this route.
- `strip_realm`: emits `strip` or `nostrip` for the generated realm blocks.
- `pool_strategy`: overrides the upstream default for this route.
- `status_check`: overrides the upstream default for this route.
- `servers`: ordered upstream home server names from `radius.upstream.servers`.

If `routes` is empty and `radius.upstream.enabled` is true, AegisNAS generates a
single `legacy-default` route from `radius.upstream.realm`, all configured
servers, and the upstream default pool/status settings.

## Generated FreeRADIUS Behavior

For each enabled route AegisNAS generates:

- one `home_server_pool`
- route-scoped `home_server` entries
- one `realm` block for `realm`
- additional `realm` blocks for every `match_realms` value
- `DEFAULT` and `NULL` realm blocks when `default: true`

The generated `sites-enabled/default` and `sites-enabled/inner-tunnel` files run
the FreeRADIUS `suffix` module first. If a configured realm matches, that realm
controls `Proxy-To-Realm`. AegisNAS sets `Proxy-To-Realm` only when a default
route exists and no previous realm match has selected a target.

`proxy.conf` is generated with `default_fallback = no`. NAS-0015 adds
`radius.upstream.transport_policy` on top of this route table so mixed UDP and
RadSec pools cannot silently downgrade traffic unless that exception is
explicitly approved. See [radius-transport-policy.md](radius-transport-policy.md).

## Validation

Config validation fails before generation when:

- upstream proxying is enabled without servers
- an enabled route has no name, realm, or server binding
- a route references an unknown upstream server
- two enabled routes claim the same realm or alias
- more than one enabled route is marked as default
- pool strategy or status-check values are invalid

The API never returns shared secrets. Use:

```text
GET /api/v1/system/proxy-routes
```

Production readiness includes `radius_proxy_routes`.

Transport downgrade readiness is reported separately as
`radius_transport_policy`.

## Standards And Vendor Scope

This feature implements the standards-side proxy routing foundation used by
vendors and federations that rely on RADIUS realm routing:

- RFC 2865 RADIUS
- RFC 2866 Accounting when proxied upstream
- RFC 2869 realm-related extended operation in FreeRADIUS deployments
- RFC 6614 RadSec when upstream home servers use `transport: radsec`

Vendor-specific policy attributes remain owned by vendor packs and VSA handling.
NAS-0010 routes packets to the correct upstream realm and pool; it does not by
itself claim full semantic support for every vendor dictionary.

## Release Certification Checklist Location

External interop and lab evidence are tracked separately in
`nas-0010-release-certification-checklist.md`.
