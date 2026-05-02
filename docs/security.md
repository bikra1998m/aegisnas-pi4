# Security Hardening

## Admin Access

Admin access now supports:

- bearer tokens
- OIDC admin SSO
- SAML admin SSO

Keep token login available as break-glass access even when SSO is enabled.

### Admin Tokens

Admin API access uses bearer tokens stored as `sha256:<hex>` digests in SQLite. Set a long bootstrap token before seeding:

```bash
export AEGIS_ADMIN_BOOTSTRAP_TOKEN="$(openssl rand -hex 32)"
aegis-admin seed --config /etc/aegisnas/config.yaml
```

Rotate tokens by inserting a new digest into `api_tokens`, confirming login, and disabling the old token. Legacy plaintext tokens are accepted only for compatibility with old databases and should be rotated out.

### Admin SSO

For OIDC or SAML deployments:

- keep the callback origin inside `AEGIS_ADMIN_ALLOWED_ORIGINS`
- keep IdP metadata, issuer URLs, and redirect targets on TLS
- use `client_secret_env` for confidential OIDC clients
- keep a tested token-login path in reserve before enforcing SSO-only operator workflows

The SAML runtime publishes service-provider metadata at:

```text
/api/v1/auth/sso/metadata
```

Protect IdP configuration, assertion attribute mappings, and delegated-admin group mappings as security-sensitive settings.

## CORS

The admin API no longer allows wildcard credentials. By default it allows:

- `https://aegis.local`
- `http://localhost:5173`
- `http://127.0.0.1:5173`

For production, set the exact UI origins:

```bash
export AEGIS_ADMIN_ALLOWED_ORIGINS="https://admin.example.net"
```

Do not leave development origins enabled on customer-facing systems.

## Signed Configuration Revisions

Configuration revision signing is supported through HMAC-SHA256. Set one of:

```bash
export AEGIS_REVISION_SIGNING_KEY="replace-with-random-key"
```

or place the key at `/etc/aegisnas/revision.key`.

Every staged apply and rollback creates a config revision snapshot. Rollback verifies the stored checksum before restoring.

## Integration Secrets

Keep integration secrets out of handwritten runbooks and ad hoc shell history. Prefer `/etc/default/aegisnas`, systemd drop-ins, or another root-readable secret source.

Important environment-backed secrets now include:

- `AEGIS_AI_API_KEY`
- `AEGIS_ADMIN_SSO_CLIENT_SECRET`
- `AEGIS_CA_ENROLLMENT_TOKEN`
- `AEGIS_MDM_API_TOKEN`
- `AEGIS_COMPLIANCE_WEBHOOK_TOKEN`
- `AEGIS_SIEM_API_KEY`
- `AEGIS_CONTROLLER_API_TOKEN`

Restrict these files to root-readable permissions and rotate them as part of site handoff or incident response.

## Management VLAN Isolation

Administrative access must stay on VLAN 40 by default. Guest and corporate VLANs should not reach SSH, admin API, health endpoints, or snap control surfaces unless an explicit site policy allows it.

## LDAP

Prefer `ldaps://` for production. The LDAP client uses TLS verification by default; install the directory CA into the OS trust store on the appliance.

## Firewall

- Guest traffic must not reach management or corporate networks by default.
- Corporate traffic should be allowed only by explicit policy.
- Captive portal pre-auth traffic should allow DNS, portal, and defined wall-garden destinations only.
- Management access should remain limited to the admin port, approved health endpoints, and explicit operator paths.

## Delegated Admin And Tenant Scope

Delegated-admin runtime now supports:

- `super_admin`
- `ops_admin`
- `guest_admin`
- `read_only`

When multi-tenant governance is enabled:

- keep `tenant_claim` mappings accurate
- review `Admin Access` regularly
- confirm guest, device, and session operations are tenant-scoped as intended

Treat group-claim and tenant-claim mappings as part of the authorization boundary, not only as convenience metadata.

## Onboarding And External CA

Certificate workflows now support internal and external CA mode.

For external CA mode:

- use HTTPS for `onboarding.ca_enrollment_url`
- keep bearer tokens in `onboarding.ca_enrollment_token_env`
- validate the returned certificate chain before broad rollout
- protect downloaded device bundles as credentials

For internal CA mode:

- protect CA private keys with root-only access
- treat backup and restore of CA material as a high-sensitivity workflow

## MDM, Compliance, SIEM, And Controller Integrations

When enabling MDM sync, compliance webhooks, SIEM export, or controller automation:

- keep endpoints on TLS
- use bearer tokens from environment variables
- validate vendor certificates where possible
- alert on degraded sync or export state
- test failure behavior so the team understands the non-blocking degrade model

These integrations should never silently become the only place where critical state exists.

## Backups

Backups are not encrypted by the application. Store archives in encrypted storage or wrap them with site-standard encryption before moving them off-device.

## AI Plane

The AI engine is advisory only. If AI Lite, full AI, the provider endpoint, or a remote webhook fails, authentication, session enforcement, and traffic admission continue.

Full AI mode sends a bounded operational snapshot to the configured provider. Keep provider keys in `/etc/default/aegisnas` through `AEGIS_AI_API_KEY`, restrict that file to root-readable permissions, and use a private endpoint when customer policy forbids cloud analysis.
