# Password And Supplicant Lifecycle

NAS-0028 adds the software layer for password lifecycle checks and signed
supplicant profile delivery. It covers Windows, macOS, iOS, Android, and Linux
profile packages, EAP method policy, trust-anchor pinning, RADIUS server-name
matching, verifier compatibility, password-change gating, and audit history.

## What It Solves

Enterprise Wi-Fi deployments fail in messy ways when users keep expired
passwords, install profiles that trust the wrong RADIUS server, or use a
supplicant profile that does not match the backend verifier. This feature makes
those decisions explicit before profile delivery:

- expired passwords return a password-change-required decision
- password changes require TLS, old-password proof, new-password policy, and
  MFA when configured
- password-based EAP methods require compatible verifiers
- EAP-TLS profiles require the certificate lifecycle feature
- profiles require server names and SHA-256 trust-anchor pins when pinning is
  enabled
- profile packages are signed with `profile_signing_key_ref`
- audit and profile-delivery inventory store hashes, not raw usernames,
  passwords, or profile contents

## Standards And Vendors

The software path supports the behavior used by Microsoft, Apple, Android,
Linux NetworkManager, Microsoft Intune, Jamf, Workspace ONE, Cisco ISE, Aruba
ClearPass, Fortinet, and Juniper Mist style onboarding.

Relevant standards include RFC 3748, RFC 5216, RFC 5280, RFC 9190, and HMAC
signature handling from RFC 2104.

## Configuration

```yaml
onboarding:
  supplicant_lifecycle:
    enabled: true
    mode: enforce
    fail_closed: true
    ssid: AegisNAS-Enterprise
    allowed_platforms: [windows, macos, ios, android, linux]
    allowed_eap_methods: [tls, peap, ttls]
    anonymous_identity: anonymous@example.com
    server_names: [radius.example.com]
    trust_anchor_pins:
      - sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    require_trust_anchor_pinning: true
    require_tls_for_delivery: true
    require_signed_profiles: true
    profile_signing_key_ref: env:AEGIS_SUPPLICANT_PROFILE_SIGNING_KEY
```

`mode: monitor` records warnings without blocking delivery. `mode: enforce`
with `fail_closed: true` rejects unsafe profile delivery and password-change
requests.

## APIs

- `GET /api/v1/system/supplicant-lifecycle`
- `POST /api/v1/system/supplicant-lifecycle/evaluate`
- `POST /api/v1/system/supplicant-lifecycle/profile`

The profile endpoint returns a signed JSON package containing the manifest,
platform-specific payload, content hash, signature, and signing-key
fingerprint. It never includes a user password.

## Portal Delivery

When the onboarding portal is enabled, authenticated users can download signed
profile packages from `/onboarding/profile/{platform}`. Portal delivery uses
the same policy engine and writes the same audit history as the admin API.

## Stored State

`supplicant_lifecycle_events` stores bounded decision history with hashed
user/device identifiers. `supplicant_profile_deliveries` stores the latest
bounded profile-delivery inventory, profile content hash, signature
fingerprint, status, platform, and expiry.

## Release Certification

Software implementation is complete when code, API, UI, tests, CI, docs, and
automation pass. Real supplicant installs, controller/AP smoke tests, MDM
packaging, HA, performance, soak, security review, and customer acceptance are
tracked separately in
`nas-0028-release-certification-checklist.md`.
