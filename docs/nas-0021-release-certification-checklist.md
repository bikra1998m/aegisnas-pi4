# NAS-0021 Release Certification Checklist

## Software Implementation

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes

Completed software scope:

- WebAuthn/passkey configuration, validation, defaults, and example config.
- Schema v26 for admin passkey credentials, challenges, and audit events.
- Registration ceremony with CBOR attestation parsing and COSE public-key storage.
- Authentication ceremony with client data, RP ID hash, user presence, user verification, ES256/RS256 signature, and replay counter checks.
- Token-login and SSO step-up flow that mints short-lived verified admin sessions only after assertion success.
- Middleware enforcement for static bearer-token bypass prevention in enforce mode.
- REST APIs, OpenAPI, RBAC, system status, support bundle, and production readiness.
- Admin UI login step-up, passkey enrollment/revocation, dashboard status, and Access Settings controls.
- Unit and integration tests for config, migrations, WebAuthn packet-shaped ceremonies, API, RBAC, readiness, OpenAPI, and support-bundle capture.
- CI target `make test-admin-webauthn`.

## External Certification / Deployment

- [ ] Validate on production Linux with HTTPS admin origin and reverse proxy headers.
- [ ] Validate Chromium, Firefox, Safari, Windows Hello, macOS Touch ID, Android, iOS, and hardware security keys.
- [ ] Capture registration and assertion ceremonies for release evidence.
- [ ] Validate OIDC and SAML SSO step-up against production identity providers.
- [ ] Validate break-glass storage, access procedure, rotation, and post-use audit.
- [ ] Run HA failover during pending challenge and active verified admin session.
- [ ] Run load and abuse tests for pending challenge limits and audit retention.
- [ ] Run security review for origin/RP ID, replay, token bypass, CSRF-adjacent login flows, and recovery governance.
- [ ] Run customer acceptance testing for privileged admin enrollment, lost authenticator, revoke, and re-enroll procedures.

External validation does not block closure of NAS-0021 software engineering work.
