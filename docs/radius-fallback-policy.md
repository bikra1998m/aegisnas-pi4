# Upstream Outage Fallback Policy

Feature ID: NAS-0016

## Purpose

The upstream outage fallback policy controls what happens when captive portal
logins are configured to authenticate through the local RADIUS broker and that
broker path is unavailable. Without this policy, `portal.local_fallback: true`
can become a broad bypass during an upstream AAA outage. NAS-0016 makes fallback
explicit, bounded, audited, and production-gated.

The policy solves four operational problems:

- only approved local or LDAP identities can be used during outage fallback
- fallback is time-bounded with a maximum outage window
- monitor mode records would-block decisions before enforcement
- every granted or denied fallback decision is persisted without storing the
  cleartext username

## Standards And Vendors

- RFC 2865: RADIUS authentication and Access-Request broker behavior.
- RFC 5080: operational retry and failure-handling guidance.
- RFC 6614: RadSec upstream transport when the broker path uses TLS-backed home
  servers.
- FreeRADIUS standard dictionaries and vendor dictionaries remain active on the
  normal broker path. Fallback itself is an AegisNAS policy decision, not a new
  wire attribute.

Enterprise products from Cisco, Aruba/HPE, Juniper, Fortinet, Ruckus, Huawei,
MikroTik, Ubiquiti, and ISP/BNG ecosystems commonly provide break-glass or local
survivability behavior. AegisNAS treats that behavior as a policy-governed
outage path rather than an implicit local bypass.

## Configuration

```yaml
radius:
  upstream:
    fallback_policy:
      enabled: true
      mode: enforce        # monitor or enforce
      fail_closed: true
      allow_portal_local: true
      allow_ldap: false
      require_identity_allowlist: true
      max_outage_seconds: 900
      stale_policy_seconds: 3600
      recovery_successes: 2
      allowed_users:
        - breakglass@example.com
      allowed_realms:
        - guest.example.com
      allowed_roles:
        - guest-basic
      audit_enabled: true
      retention_limit: 6000
portal:
  radius_auth: true
  local_fallback: true
```

`monitor` mode preserves legacy fallback behavior while auditing identities that
would be denied by enforcement. `enforce` mode denies fallback unless the source,
allowlist, and outage window all match. Production readiness requires enforce
mode, `fail_closed: true`, an identity allowlist when required, and audit
storage.

## Runtime Behavior

1. Portal login first tries local admin break-glass for admin users.
2. When `portal.radius_auth` is enabled, the portal sends PAP credentials to the
   local RADIUS broker.
3. If broker auth succeeds, normal Access-Accept or Access-Reject behavior is
   used.
4. If broker auth is unavailable and `portal.local_fallback` is enabled, AegisNAS
   checks local users and LDAP.
5. If a local or LDAP identity validates, `radius.upstream.fallback_policy`
   evaluates the identity source, user, realm, role, and outage window.
6. The decision is recorded in `radius_fallback_events` using a SHA-256 hash of
   the normalized username.

The policy does not store passwords or cleartext usernames in fallback audit
events.

## API

- `GET /api/v1/system/fallback-policy`
- `GET /api/v1/system/fallback-policy?decision=allowed&limit=100`
- `GET /api/v1/system/fallback-policy?source=portal`

The endpoint is read-only for admin roles. The same summary appears in:

- `/api/v1/system/status` as `radius.fallback_policy`
- `/api/v1/system/production-readiness` as `radius_fallback_policy`
- the admin dashboard Upstream AAA panel
- support bundles as `api/fallback-policy.json`

## Database

NAS-0016 adds schema version 21 with `radius_fallback_events`.

Stored fields include:

- observation time and source
- hashed username
- realm, identity source, and role
- decision and reason
- upstream status and policy mode
- outage start and expiry timestamps
- structured details JSON

Retention is bounded by `radius.upstream.fallback_policy.retention_limit`.

## High Availability

Fallback decisions are stored in the configured database. HA deployments should
use the same shared or replicated data-plane requirements as accounting spool
and upstream AAA history. External HA validation is tracked in
`nas-0016-release-certification-checklist.md`.

## Software Completion

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes

External certification does not block closure of NAS-0016.
