# EAP Method Framework

NAS-0022 adds a typed EAP control plane around the generated FreeRADIUS EAP
configuration. NAS-0023 extends this control plane with opt-in TEAP method
chaining. NAS-0024 adds opt-in EAP-FAST and EAP-PWD policy. NAS-0025 adds
opt-in EAP-SIM, EAP-AKA, and EAP-AKA-prime policy. NAS-0026 adds
machine/user authentication correlation on top of TEAP and 802.1X evidence.

## What It Solves

The framework makes EAP behavior explicit:

- which outer methods are allowed
- which tunneled inner methods are allowed
- which identity source owns each method
- whether `Message-Authenticator` is required for EAP packets
- whether a client certificate is required
- whether unsupported methods are rejected, NAKed, or monitored
- whether TEAP machine/user method chaining is generated and safe
- whether machine and user authentication evidence can be correlated safely
- whether EAP-FAST PAC policy and EAP-PWD password-proof policy are generated
  and safe
- whether EAP-SIM/AKA vector provider, pseudonym, resync, and AKA-prime KDF
  policy are generated and safe
- which recent method decisions need operator attention

## Supported Engineering Scope

Generated methods in this release:

- PEAP with MSCHAPv2, GTC, or TLS inner policy
- EAP-TTLS with MSCHAPv2, PAP, CHAP, GTC, or TLS inner policy
- EAP-TLS framework binding to certificate identity
- TEAP with RFC 7170 method-chain policy, cryptobinding checks, and bounded
  chain telemetry
- EAP-FAST with RFC 4851 PAC policy, cryptobinding checks, and bounded method
  telemetry
- EAP-PWD with RFC 5931 group policy, password-proof checks, replay checks, and
  bounded method telemetry
- EAP-SIM, EAP-AKA, and EAP-AKA-prime with RFC 4186, RFC 4187, and RFC 5448
  vector-provider policy, identity privacy controls, resync handling,
  AKA-prime network binding, and bounded method telemetry
- machine/user authentication correlation with fresh machine evidence,
  same-client binding, transition windows, deterministic role merge, conflict
  handling, current-state tracking, and bounded telemetry

## Configuration

```yaml
radius:
  eap:
    default_type: peap
    peap_inner: mschapv2
    ttls_inner: pap
    tls_min_version: "1.2"
    tls_max_version: "1.3"
    teap:
      enabled: true
      default_inner_method: mschapv2
      chain_mode: machine_then_user
      require_crypto_binding: true
      require_identity_type: true
      require_machine_identity: true
      require_user_identity: true
      allow_pac: true
      pac_provisioning: authenticated
      max_chain_steps: 2
      session_ttl_seconds: 900
    machine_user:
      enabled: true
      mode: enforce
      fail_closed: true
      correlation_mode: machine_then_user
      require_teap: true
      require_machine_identity: true
      require_user_identity: true
      require_machine_before_user: true
      require_same_calling_station: true
      require_fresh_machine_auth: true
      machine_auth_ttl_seconds: 28800
      transition_window_seconds: 900
      role_merge_strategy: user_primary
      conflict_action: reject
    fast:
      enabled: true
      default_inner_method: mschapv2
      require_crypto_binding: true
      allow_pac: true
      pac_provisioning: authenticated
      allow_anonymous_provisioning: false
      allow_eap_payload: true
    pwd:
      enabled: true
      group: 19
      server_id: aegisnas-pwd
      require_strong_group: true
      password_source: identity-failover
      require_password_proof: true
      replay_window_seconds: 30
    sim_aka:
      enabled: true
      methods: ["sim", "aka", "aka-prime"]
      require_identity: true
      require_permanent_identity: true
      allow_pseudonym_identity: true
      vector_provider: external-http
      vector_provider_ref: env:AEGIS_SIMAKA_VECTOR_PROVIDER_URL
      require_fresh_vectors: true
      max_vector_age_seconds: 300
      min_triplets: 2
      min_quintuplets: 1
      allow_resynchronization: true
      require_network_name: true
      network_name: wlan.mnc001.mcc001.3gppnetwork.org
      require_kdf: true
      fail_on_provider_unavailable: true
    framework:
      enabled: true
      mode: enforce
      fail_closed: true
      allowed_methods: ["peap", "ttls", "tls"]
      allowed_inner_methods: ["mschapv2", "pap", "chap", "gtc", "tls"]
      default_outer_identity_source: configured-default
      default_inner_identity_source: identity-failover
      unsupported_method_action: reject
      require_message_authenticator: true
      require_identity_binding: true
      telemetry_enabled: true
      event_retention_limit: 6000
      method_timeout_seconds: 60
      fragment_size: 1024
```

Use `mode: monitor` while introducing new APs, switches, or supplicant
profiles. Use `mode: enforce` with `fail_closed: true` for production.

## API

```text
GET  /api/v1/system/eap-framework
POST /api/v1/system/eap-framework/evaluate
GET  /api/v1/system/eap-framework/teap
POST /api/v1/system/eap-framework/teap/evaluate
GET  /api/v1/system/eap-framework/machine-user
POST /api/v1/system/eap-framework/machine-user/evaluate
GET  /api/v1/system/eap-framework/fast-pwd
POST /api/v1/system/eap-framework/fast-pwd/evaluate
GET  /api/v1/system/eap-framework/sim-aka
POST /api/v1/system/eap-framework/sim-aka/evaluate
```

The `GET` response includes the catalog, effective policy, identity-source
bindings, vendor compatibility profiles, runtime summary, and recent events.

The `evaluate` endpoint accepts RADIUS-like fields such as method,
inner method, NAS type, `EAP-Message` presence, `Message-Authenticator`
presence, certificate state, identity source, and optional audit recording.

The TEAP endpoints expose RFC 7170 TLV coverage, chain policy, recent TEAP
events, and deterministic machine/user chain evaluation. See
[teap-method-chaining.md](teap-method-chaining.md).

The machine/user endpoints expose correlation policy, current correlation
state, recent decisions, role-merge behavior, stale-machine handling, and
deterministic evaluation. See
[eap-machine-user-correlation.md](eap-machine-user-correlation.md).

The FAST/PWD endpoints expose RFC 4851 and RFC 5931 policy, PAC and password
proof coverage, recent FAST/PWD events, and deterministic method evaluation.
See [eap-fast-pwd.md](eap-fast-pwd.md).

The SIM/AKA endpoints expose RFC 4186, RFC 4187, and RFC 5448 policy, vector
provider and identity privacy controls, recent SIM/AKA events, and
deterministic method evaluation. See [eap-sim-aka.md](eap-sim-aka.md).

## Stored State

`eap_method_events` stores hashed identities and recent method decisions:

- accepted
- rejected
- monitor_allowed
- unsupported

The table intentionally stores `user_name_hash` and `calling_station_hash`, not
raw subscriber identifiers.

Method-family telemetry is stored in bounded tables:

- `eap_teap_chain_events`
- `eap_machine_user_correlations`
- `eap_machine_user_session_state`
- `eap_fast_pwd_events`
- `eap_sim_aka_events`

The SIM/AKA table stores hashes for permanent identities, pseudonyms, reauth
identities, network names, and calling-station IDs.

## FreeRADIUS Generation

`mods-enabled/eap` now includes framework evidence comments and uses the
framework's effective method timeout, fragment size, and max session limit.

If enforce/fail-closed mode allows a method that this software release cannot
generate, FreeRADIUS generation fails before apply.

## Production Notes

- Keep `radius.packet_hardening.require_message_authenticator` at `auto` or
  stricter.
- Keep planned methods out of `allowed_methods` until their roadmap feature is
  implemented.
- Add `teap` to `allowed_methods` only after TEAP supplicant/AP smoke tests.
- Put `radius.eap.machine_user.mode` in `enforce` only after machine and user
  authentication transitions have been tested for the target client fleet.
- Add `fast` or `pwd` to `allowed_methods` only after method-specific
  supplicant/AP smoke tests.
- Add `sim`, `aka`, or `aka-prime` only after `radius.eap.sim_aka` has a real
  vector provider reference and carrier/offload lab coverage.
- Enable CRL or OCSP before making production EAP-TLS certificate claims.
- Retain `api/eap-framework.json` from support bundles as release evidence.
- Retain `api/eap-framework-teap.json` when TEAP is enabled.
- Retain `api/eap-framework-machine-user.json` when machine/user correlation is
  enabled.
- Retain `api/eap-framework-fast-pwd.json` when FAST or PWD is enabled.
- Retain `api/eap-framework-sim-aka.json` when SIM, AKA, or AKA-prime is
  enabled.
