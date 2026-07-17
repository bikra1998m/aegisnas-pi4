# Admin WebAuthn Passkeys

NAS-0021 adds phishing-resistant WebAuthn/passkey MFA for AegisNAS administrative sessions.

## What It Protects

Admin passkeys protect privileged browser sessions after the first factor succeeds:

- token login through `POST /api/v1/auth/token/start`
- OIDC or SAML admin SSO callback
- privileged roles listed in `admin_webauthn.require_for_roles`

When enforcement is enabled, the first factor creates only a pending WebAuthn challenge. A short-lived admin session token is minted only after the browser returns a valid WebAuthn assertion.

## Configuration

```yaml
admin_webauthn:
  enabled: true
  mode: enforce
  fail_closed: true
  rp_id: admin.example.com
  rp_name: AegisNAS Admin
  origins:
    - https://admin.example.com
  challenge_ttl_seconds: 300
  session_ttl_seconds: 28800
  max_pending: 10000
  user_verification: preferred
  attestation: none
  resident_key: preferred
  require_for_roles:
    - super_admin
    - ops_admin
  require_for_sso: true
  require_for_token_login: true
  break_glass_allowed: false
  audit_enabled: true
  retention_limit: 6000
```

`rp_id` must match the admin UI host or a registrable parent domain. `origins` must be HTTPS origins, except localhost lab origins.

## Operator Flow

1. Set `admin_webauthn.enabled: true` and `mode: monitor`.
2. Configure the production `rp_id` and HTTPS admin `origins`.
3. Sign in as a super admin and open Admin Access.
4. Register passkeys for privileged admins.
5. Confirm `/api/v1/system/webauthn` reports enabled credentials.
6. Switch to `mode: enforce` and keep `fail_closed: true`.
7. Review production readiness and support bundle `api/webauthn.json`.

## API

Public login ceremony:

```text
POST /api/v1/auth/token/start
POST /api/v1/auth/webauthn/login/options
POST /api/v1/auth/webauthn/login/finish
```

Protected management ceremony:

```text
GET    /api/v1/system/webauthn
POST   /api/v1/system/webauthn/register/options
POST   /api/v1/system/webauthn/register/finish
DELETE /api/v1/system/webauthn/credentials/{id}
```

## Stored State

- `admin_webauthn_credentials`: credential ID hash, COSE public key, sign counter, transports, AAGUID, status, and timestamps.
- `admin_webauthn_challenges`: one-time registration/authentication challenge state.
- `admin_webauthn_events`: hashed audit decisions for challenge issue, registration, acceptance, denial, and monitor allowance.

Credential private keys never leave the authenticator. AegisNAS stores only public keys and non-secret credential identifiers.

## Verification Behavior

AegisNAS verifies:

- `clientDataJSON.type`
- challenge binding
- allowed origin
- RP ID hash
- user presence
- user verification when required
- credential subject binding
- ES256 and RS256 assertion signatures
- signature counter replay when counters are non-zero

## Break-Glass

`break_glass_allowed` can keep static bearer-token recovery available during deployment. Production readiness degrades while this is enabled. Store break-glass tokens offline, rotate them after use, and keep the release certification evidence with the deployment record.
