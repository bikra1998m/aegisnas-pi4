# EAP-FAST And EAP-PWD

NAS-0024 makes EAP-FAST and EAP-PWD opt-in generated methods in the EAP
framework. The software implementation includes configuration validation,
policy evaluation, generated FreeRADIUS sections, bounded audit history,
readiness checks, API visibility, dashboard status, admin UI controls, and CI
coverage. External supplicant, AP/controller, and FreeRADIUS-on-Linux evidence
is tracked separately in `nas-0024-release-certification-checklist.md`.

## What It Solves

EAP-FAST provides a protected tunnel with Protected Access Credential policy for
older Cisco-originated enterprise deployments and embedded Wi-Fi clients that
still require FAST. AegisNAS governs whether FAST is generated, which inner
method is used, whether cryptobinding is required, whether PACs are allowed or
required, how PAC provisioning is treated, and how many provisioning attempts
are accepted.

EAP-PWD provides password-authenticated key exchange without a client
certificate. AegisNAS governs the PWD group, server identity, identity
requirement, local verifier requirement, password proof validation, replay
handling, and event retention.

## Standards And Dictionaries

- RFC 4851: EAP-FAST.
- RFC 5931: EAP-PWD.
- RFC 3748: EAP base protocol.
- RFC 2865: RADIUS Access-Request and Access-Challenge transport.
- FreeRADIUS EAP modules `rlm_eap_fast` and `rlm_eap_pwd`.
- FreeRADIUS internal EAP-FAST attribute namespace for PAC, PAC key material,
  PAC opaque state, PAC lifetime, PAC acknowledgement, cryptobinding, and
  EAP-Payload telemetry.

## Configuration

FAST and PWD are available by default but not generated until the methods are
added to `radius.eap.framework.allowed_methods`:

```yaml
radius:
  eap:
    default_type: fast
    fast:
      enabled: true
      default_inner_method: mschapv2
      require_crypto_binding: true
      allow_pac: true
      require_pac: false
      pac_provisioning: authenticated
      pac_authority_id: aegisnas-fast
      pac_lifetime_seconds: 2592000
      pac_opaque_key_ref: ""
      allow_anonymous_provisioning: false
      allow_eap_payload: true
      max_provisioning_attempts: 3
      session_ttl_seconds: 900
      event_retention_limit: 6000
    pwd:
      enabled: true
      group: 19
      server_id: aegisnas-pwd
      require_strong_group: true
      password_source: identity-failover
      allow_local_verifier: true
      require_identity: true
      require_password_proof: true
      replay_window_seconds: 30
      fragment_size: 1020
      event_retention_limit: 6000
    framework:
      enabled: true
      mode: enforce
      fail_closed: true
      allowed_methods: ["peap", "ttls", "tls", "fast", "pwd"]
      allowed_inner_methods: ["mschapv2", "pap", "chap", "gtc", "tls"]
      require_message_authenticator: true
      require_identity_binding: true
```

Use `mode: monitor` while introducing a new supplicant or NAS family. Use
`mode: enforce` with `fail_closed: true` for production.

## API

```text
GET  /api/v1/system/eap-framework/fast-pwd
POST /api/v1/system/eap-framework/fast-pwd/evaluate
```

The `GET` endpoint returns FAST policy, PWD policy, attribute capability
coverage, runtime counters, release evidence requirements, and recent audited
events.

The `evaluate` endpoint accepts method facts such as method, inner method,
identity, NAS type, `EAP-Message`, `Message-Authenticator`, TLS version,
cryptobinding state, PAC state, PWD group, password proof state, replay state,
and optional audit recording. Raw identities are never persisted; the database
stores SHA-256 hashes only.

The general EAP evaluation endpoint also routes `method: fast` and
`method: pwd` through the FAST/PWD evaluator.

## FreeRADIUS Generation

When FAST or PWD is allowed and policy is healthy, generated `mods-enabled/eap`
includes conservative method blocks:

- `fast` uses `tls-common`, `inner-tunnel`, and the configured default inner
  method.
- `pwd` uses the configured group, server ID, and fragment size.

AegisNAS fails generation in enforce/fail-closed mode when FAST or PWD is
allowed but required safety controls are disabled.

## Stored State

`eap_fast_pwd_events` stores:

- method, decision, reason, NAS identifier, and NAS type
- hashed identity and calling station
- identity source, inner method, TLS version, and policy mode
- FAST cryptobinding, PAC, PAC provisioning, anonymous provisioning, and
  EAP-Payload evidence
- PWD password proof, replay state, group, and hashed server ID
- latency and bounded details

Retention is controlled by `radius.eap.fast.event_retention_limit` or
`radius.eap.pwd.event_retention_limit`, falling back to the generic EAP
framework retention limit when unset.

## Production Notes

- Keep `require_crypto_binding: true` for all production EAP-FAST profiles.
- Keep `allow_anonymous_provisioning: false` unless a lab-certified migration
  profile requires it.
- Keep `require_strong_group: true` for EAP-PWD.
- Keep `require_password_proof: true` and `replay_window_seconds` positive for
  EAP-PWD production profiles.
- Capture `api/eap-framework-fast-pwd.json` in support bundles for release
  evidence.
