# TEAP Method Chaining

NAS-0023 makes TEAP an opt-in generated EAP method with typed RFC 7170 policy,
method-chain evaluation, bounded telemetry, API visibility, and admin UI
controls. External supplicant, AP/controller, and FreeRADIUS-on-Linux evidence
is tracked separately in `nas-0023-release-certification-checklist.md`.

## What It Solves

TEAP lets an access network authenticate more than one identity inside a single
protected tunnel. Common enterprise patterns are:

- machine then user authentication for managed laptops
- machine-only access for pre-login device posture
- user-only access for BYOD
- either user or machine access during migration windows

The AegisNAS policy layer governs when TEAP may be generated, what inner method
is allowed, whether cryptobinding is mandatory, whether channel binding is
required, whether PACs are accepted or required, and which identities must be
present before access can be accepted.

## Standards And Dictionaries

- RFC 7170: Tunnel Extensible Authentication Protocol
- RFC 3748: EAP base protocol
- RFC 2865: RADIUS Access-Request and Access-Challenge transport
- FreeRADIUS dictionary namespace `FreeRADIUS` for TEAP TLVs such as
  `FreeRADIUS-EAP-TEAP-Identity-Type`,
  `FreeRADIUS-EAP-TEAP-EAP-Payload`,
  `FreeRADIUS-EAP-TEAP-Crypto-Binding`,
  `FreeRADIUS-EAP-TEAP-Channel-Binding`,
  `FreeRADIUS-EAP-TEAP-Result`,
  `FreeRADIUS-EAP-TEAP-Intermediate-Result`,
  `FreeRADIUS-EAP-TEAP-PAC`,
  `FreeRADIUS-EAP-TEAP-Basic-Password-Auth-Req`, and
  `FreeRADIUS-EAP-TEAP-Basic-Password-Auth-Resp`.

## Configuration

TEAP is available by default but not advertised until `teap` is added to the
EAP framework's allowed methods:

```yaml
radius:
  eap:
    default_type: teap
    teap:
      enabled: true
      default_inner_method: mschapv2
      chain_mode: machine_then_user
      require_crypto_binding: true
      require_channel_binding: false
      require_identity_type: true
      require_machine_identity: true
      require_user_identity: true
      allow_pac: true
      require_pac: false
      pac_provisioning: authenticated
      pac_authority_id: aegisnas-teap
      pac_lifetime_seconds: 2592000
      allow_eap_payload: true
      allow_basic_password_auth: false
      max_chain_steps: 2
      session_ttl_seconds: 900
      event_retention_limit: 6000
    framework:
      enabled: true
      mode: enforce
      fail_closed: true
      allowed_methods: ["peap", "ttls", "tls", "teap"]
      allowed_inner_methods: ["mschapv2", "pap", "chap", "gtc", "tls"]
      require_message_authenticator: true
      require_identity_binding: true
```

`mode: monitor` records decisions without hard rejection. Production TEAP SSIDs
should use `mode: enforce` with `fail_closed: true`.

## API

```text
GET  /api/v1/system/eap-framework/teap
POST /api/v1/system/eap-framework/teap/evaluate
```

The `GET` endpoint returns policy, RFC 7170 TLV coverage, runtime summary, and
recent audited TEAP chain events.

The `evaluate` endpoint accepts TEAP chain facts such as machine identity, user
identity, inner method, `Message-Authenticator`, TLS version, cryptobinding,
channel-binding, PAC state, Identity-Type, Result TLVs, and optional audit
recording. Raw identities are never persisted; the database stores SHA-256
hashes only.

## FreeRADIUS Generation

When TEAP is allowed and policy is healthy, the generated EAP module includes a
conservative `teap` block using `tls-common` and `inner-tunnel`. AegisNAS fails
generation in enforce/fail-closed mode if TEAP is allowed but cryptobinding,
Message-Authenticator, or identity binding is unsafe.

## Stored State

`eap_teap_chain_events` stores:

- decision and reason
- chain mode and chain state
- NAS identifier and NAS type
- hashed outer, user, and machine identities
- inner method and TLS version
- cryptobinding, channel-binding, PAC, EAP-Payload, and Result TLV evidence
- latency and bounded details

Retention is controlled by `radius.eap.teap.event_retention_limit`, falling back
to the generic EAP framework retention limit when unset.

## Production Notes

- Keep `require_crypto_binding: true` for all production TEAP profiles.
- Use `machine_then_user` for managed enterprise devices.
- Keep `allow_basic_password_auth: false` unless a specific legacy supplicant
  certification requires it.
- Keep `pac_provisioning: authenticated`; avoid unauthenticated PAC enrollment.
- Capture `api/eap-framework-teap.json` in support bundles for release evidence.
