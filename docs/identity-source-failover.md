# Identity Source Failover

NAS-0019 adds deterministic identity-source routing for captive portal fallback authentication.

## What It Solves

When upstream AAA is unavailable, the portal can authenticate against local users and LDAP. Without a deterministic source plan, operators cannot prove which source was tried first, why a source was skipped, or whether a later success contradicted an earlier credential rejection.

Identity source failover provides:

- ordered source evaluation through `identity.failover.source_order`
- source health evidence in `identity_source_events`
- circuit-open protection after repeated source failures
- explicit split-result behavior when one source rejects and another accepts
- optional stale LDAP credential cache with bcrypt password hashes
- runtime visibility in API, dashboard, support bundle, and production readiness

This is a software HA feature. Real LDAP/AD/controller/device failover drills remain part of release certification.

## Configuration

```yaml
identity:
  failover:
    enabled: true
    mode: enforce
    fail_closed: true
    source_order:
      - local
      - ldap-primary
    max_failures: 3
    circuit_open_seconds: 300
    stale_cache_seconds: 3600
    cache_credentials: false
    split_result_policy: deny
    health_check_interval_seconds: 60
    audit_enabled: true
    retention_limit: 6000
```

`mode: monitor` records evidence while allowing non-disruptive migration. `mode: enforce` applies circuit-open skips and fail-closed behavior.

`split_result_policy` values:

- `deny`: deny a login if a later source accepts after an earlier credential rejection.
- `prefer_first`: keep the first credential rejection authoritative.
- `prefer_success`: allow a later accepted source to win.

`cache_credentials` is disabled by default. When enabled, successful LDAP portal credentials are cached with bcrypt password hashes and bounded expiry. Cached entries are used only if LDAP is unavailable.

## Runtime API

```text
GET /api/v1/system/identity-failover
GET /api/v1/system/identity-failover?source=ldap-primary&decision=failed&limit=100
```

The response includes:

- effective policy
- deterministic source plan
- circuit state per source
- audit summary
- stale-cache summary
- recent source decisions

The same report appears under `/api/v1/system/status` as `identity.failover`, in production readiness as `identity_source_failover`, and in support bundles as `api/identity-failover.json`.

## Database

`identity_source_events` stores hashed usernames, source name/type, decision, reason, latency, circuit state, cache use, and JSON details.

`identity_source_cache` stores hashed usernames, bcrypt password hashes, role, groups, source identity, last success, and expiry.

No plaintext passwords or raw usernames are stored in identity failover audit events.

## Operator Checks

Before production cutover:

1. Set `identity.failover.mode: enforce`.
2. Keep `fail_closed: true`.
3. Confirm `source_order` matches the intended trust order.
4. Review `/api/v1/system/identity-failover`.
5. Confirm production readiness check `identity_source_failover` passes.
6. Export a support bundle and retain `api/identity-failover.json`.

## Release Certification

Software implementation is complete when code, schema, API, UI, tests, and docs pass.

External validation belongs in [nas-0019-release-certification-checklist.md](nas-0019-release-certification-checklist.md), including real directory outages, HA replication validation, vendor smoke tests, long-duration soak, and security review.
