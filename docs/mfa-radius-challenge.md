# OTP And RADIUS Challenge MFA

NAS-0020 adds step-up MFA for portal and brokered RADIUS authentication.

## What It Does

AegisNAS can require a second factor after a successful first-factor identity decision. The first factor can come from local users, LDAP through identity failover, or an upstream RADIUS broker. The second factor can be:

- TOTP from an authenticator application.
- A one-time recovery code.
- An upstream RADIUS `Access-Challenge` transaction that carries RFC 2865 `State`.

The feature is disabled by default for upgrade safety. When enabled in `enforce` mode with `fail_closed: true`, privileged roles and configured realms must pass MFA before the portal creates a session.

## Standards And Vendor Scope

- RFC 2865: `Access-Challenge`, `State`, `Reply-Message`, `User-Password`.
- RFC 4226: HOTP algorithm used by TOTP.
- RFC 6238: TOTP time-step verification.

RADIUS challenge MFA is common across VPN, firewall, and enterprise access products including Cisco ASA/AnyConnect, Fortinet, Palo Alto Networks, Microsoft NPS extensions, Aruba/HPE, and many identity providers that front RADIUS.

## Configuration

```yaml
mfa:
  enabled: true
  mode: enforce
  fail_closed: true
  otp:
    enabled: true
    issuer: AegisNAS
    algorithm: SHA1
    digits: 6
    period_seconds: 30
    window_steps: 1
    max_attempts: 5
    sealing_key_ref: env:AEGIS_MFA_SEALING_KEY
    step_up_roles: [admin, super_admin, ops_admin]
    step_up_realms: []
    required_for_admins: true
  radius_challenge:
    enabled: true
    ttl_seconds: 300
    max_pending: 10000
    prompt: Enter one-time password
    state_bytes: 32
  recovery:
    enabled: true
    code_count: 10
    code_bytes: 16
  audit_enabled: true
  retention_limit: 6000
```

Set `AEGIS_MFA_SEALING_KEY` to at least 16 random bytes before enrollment. The resolved key is SHA-256 derived for AES-GCM sealing; the key value is never exposed through APIs or support bundles.

## API

```text
GET  /api/v1/system/mfa
GET  /api/v1/system/mfa?decision=denied&method=totp&limit=100
POST /api/v1/system/mfa/enroll
POST /api/v1/system/mfa/verify
POST /api/v1/system/mfa/recovery-codes
```

Enrollment and recovery-code rotation require `super_admin`. The enrollment response returns the TOTP secret and recovery codes once. Store them in the operator-approved enrollment channel.

## Packet Flow

For an upstream challenge, the broker preserves the RFC 2865 `State` attribute as an opaque base64url string and sends it back with the OTP in the next `Access-Request`.

For local MFA, AegisNAS creates an `aegis1.` challenge state, stores only its SHA-256 hash, and verifies the OTP or recovery code before building a local portal session.

## Data Model

- `mfa_totp_secrets`: encrypted TOTP secrets and verifier metadata.
- `mfa_recovery_codes`: bcrypt-hashed one-time recovery codes.
- `mfa_challenges`: pending, verified, expired, or failed challenge state.
- `mfa_events`: hashed-identity audit history.

## Operations

1. Set `mfa.otp.sealing_key_ref`.
2. Enable MFA in `monitor` mode.
3. Enroll required users from `/api/v1/system/mfa/enroll`.
4. Verify codes from `/api/v1/system/mfa/verify`.
5. Switch to `mode: enforce` and keep `fail_closed: true`.
6. Review `/api/v1/system/mfa`, production readiness, and support bundle `api/mfa.json`.

## Release Certification

Hardware, vendor-controller, FreeRADIUS lab, HA, performance, soak, and customer acceptance evidence are tracked in [nas-0020-release-certification-checklist.md](nas-0020-release-certification-checklist.md).
