# Active Directory Kerberos And Winbind

NAS-0018 adds Active Directory as a first-class identity source for portal and
RADIUS-adjacent authentication flows. The software implementation includes
configuration validation, LDAPS user/group lookup, Kerberos password verification
through isolated `kinit` credential caches, winbind helper verification, group
to role mapping, bounded group cache, audit history, health checks, admin API
visibility, production readiness checks, support bundle capture, and
FreeRADIUS `ldap` / `mschap` generation for PEAP-MSCHAPv2 interoperability.

External domain join, live Microsoft AD validation, real AP/controller smoke
tests, and long-duration HA/performance certification are tracked separately in
[nas-0018-release-certification-checklist.md](nas-0018-release-certification-checklist.md).

## Standards And Vendor Scope

Active Directory authentication is not a RADIUS VSA feature by itself. It is the
directory and verifier layer used by enterprise NAS vendors before they emit
standard authorization attributes such as `Filter-Id`, `Tunnel-Type`,
`Tunnel-Medium-Type`, `Tunnel-Private-Group-Id`, `Session-Timeout`, and
vendor-specific policy attributes.

Relevant standards:

- RFC 2865 and RFC 2866 for RADIUS authentication and accounting integration.
- RFC 3748 for EAP transport.
- RFC 5216 for EAP-TLS environments that use AD-backed identity.
- RFC 4120 for Kerberos.
- RFC 4511 and RFC 4515 for LDAP protocol and filters.
- PEAP/MSCHAPv2 deployments that rely on FreeRADIUS `rlm_mschap` plus
  Samba/winbind `ntlm_auth`.

Common enterprise products that use the same pattern include Microsoft NPS,
Cisco ISE, Aruba ClearPass, FortiAuthenticator, Ruckus Cloudpath, ExtremeControl,
Juniper Mist Access Assurance, and FreeRADIUS deployments joined to AD.

## Configuration

Minimal LDAPS bind mode:

```yaml
active_directory:
  enabled: true
  mode: enforce
  fail_closed: true
  domain: corp.example.com
  realm: CORP.EXAMPLE.COM
  netbios_domain: CORP
  ldap_url: ldaps://dc1.corp.example.com:636
  base_dn: dc=corp,dc=example,dc=com
  bind_dn: cn=aegisnas,ou=svc,dc=corp,dc=example,dc=com
  bind_password_ref: env:AEGIS_AD_BIND_PASSWORD
  require_ldaps: true
  auth_method: ldap_bind
  group_role_mappings:
    AegisNAS-Employees: employee
    AegisNAS-Admins: admin

identity:
  failover:
    enabled: true
    mode: enforce
    fail_closed: true
    source_order: [active-directory, local]
```

Kerberos password verifier:

```yaml
active_directory:
  enabled: true
  auth_method: kerberos
  kerberos:
    enabled: true
    kinit_path: kinit
    kdestroy_path: kdestroy
    krb5_config_path: /etc/krb5.conf
    credential_cache_dir: /run/aegisnas/krb5
```

Winbind helper verifier:

```yaml
active_directory:
  enabled: true
  auth_method: winbind_helper
  winbind:
    enabled: true
    domain_join_required: true
    wbinfo_path: wbinfo
    ntlm_auth_path: /usr/bin/ntlm_auth
    auth_helper_path: /usr/local/libexec/aegisnas-ad-auth
```

The helper receives the password on stdin, not as a command-line argument. It
should exit `0` for accepted credentials and may emit `GROUP=<name>` lines for
group membership. If no groups are returned and LDAPS is configured, AegisNAS
falls back to LDAPS group lookup.

## Runtime Behavior

The identity failover source type is `active_directory`. The canonical source
name is `active-directory`.

Authentication flow:

1. Identity failover builds a deterministic source plan.
2. Active Directory normalizes `DOMAIN\user`, `user@realm`, and short names.
3. The configured verifier runs:
   - `ldap_bind`: service bind, user search, user bind, group search.
   - `kerberos`: isolated temporary credential cache, password via stdin,
     cleanup with `kdestroy`, optional LDAPS group lookup.
   - `winbind_helper`: helper with password via stdin, optional LDAPS group
     lookup.
4. Groups are mapped to roles through `group_role_mappings`.
5. Successful groups are stored in `active_directory_group_cache`.
6. Every decision is recorded in `active_directory_events` with hashed identity
   and principal values.
7. The portal records the source decision in `identity_source_events`.

FreeRADIUS generation:

- `mods-enabled/ldap` uses the AD LDAPS configuration when local LDAP is not
  enabled.
- `mods-enabled/mschap` includes `ntlm_auth` when AD winbind is enabled.
- `sites-enabled/default` and `inner-tunnel` continue to use the generated LDAP
  and MSCHAP modules for PEAP/MSCHAPv2 flows.

## Database Tables

- `active_directory_events`: bounded audit records for accepted, rejected,
  not-found, failed, skipped, and cache-used decisions.
- `active_directory_group_cache`: bounded group and role cache keyed by source
  and hashed username.
- `active_directory_health_checks`: recorded configuration, DNS, Kerberos, and
  winbind health probes.

Schema migration version: `24`.

## Admin API

```text
GET  /api/v1/system/active-directory
GET  /api/v1/system/active-directory?source=active-directory&decision=accepted&component=configuration&limit=100
POST /api/v1/system/active-directory/check
```

The status report is also available at:

- `/api/v1/system/status` under `identity.active_directory`
- `/api/v1/system/production-readiness` as `active_directory_identity`
- support bundles as `api/active-directory.json`

Read access is available to read-only and admin roles. Running health checks
requires `ops_admin` or `super_admin`.

## Security Notes

- `require_ldaps` defaults to true.
- Bind credentials support `bind_password_ref` and are discovered by secret
  provider readiness checks.
- Kerberos passwords are passed via stdin, not process arguments.
- Kerberos credential caches are isolated in temporary directories and destroyed.
- Usernames and Kerberos principals are stored as hashes in audit tables.
- Invalid command text containing newline, NUL, or unsafe path content is
  rejected by config validation.
- Enforce mode with `fail_closed` blocks production readiness when AD is not
  executable.

## Monitoring And Troubleshooting

Use:

```bash
curl -sS http://127.0.0.1:8083/api/v1/system/active-directory
curl -sS -X POST http://127.0.0.1:8083/api/v1/system/active-directory/check
```

Check these fields first:

- `status`
- `summary.source_executable`
- `summary.source_reason`
- `audit_summary.last_decision`
- `health_summary.last_status`
- `cache_summary.total_entries`

Common failures:

- `ldap_url must use ldaps://`: either enable LDAPS on the domain controller or
  explicitly disable `require_ldaps` only for a controlled lab.
- `bind_dn requires bind_password or bind_password_ref`: configure a secret
  reference for the service account.
- `kerberos verifier is disabled`: set `active_directory.kerberos.enabled`.
- `winbind helper verifier is not configured`: set
  `active_directory.winbind.auth_helper_path`.

## Automated Validation

Run:

```bash
make test-active-directory
go test ./internal/activedirectory ./internal/config ./internal/db ./internal/identity ./internal/portal/auth ./internal/radius ./internal/adminapi -run 'ActiveDirectory|ConfigValidationActiveDirectory|BuildSourcePlanIncludesActiveDirectory|AuthenticateFallbackUsesActiveDirectory|MSCHAP|OpenAPI|ProductionReadinessIncludesActiveDirectory' -count=1
```

These tests validate software behavior only. Live AD, FreeRADIUS, AP/controller,
HA, and performance evidence belongs in the release certification checklist.
