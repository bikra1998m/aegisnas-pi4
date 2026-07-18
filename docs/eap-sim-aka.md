# EAP-SIM, EAP-AKA, And EAP-AKA-prime

NAS-0025 implements the software control plane for mobile EAP methods used by
carrier offload, roaming, Passpoint, WiMAX, and telecom access deployments.

## Problem Solved

EAP-SIM, EAP-AKA, and EAP-AKA-prime authenticate subscribers with SIM or USIM
material instead of passwords or client certificates. The NAS must never treat
these as simple dictionary attributes. It needs a vector provider, identity
privacy handling, replay protection, resynchronization controls, and
method-specific validation before FreeRADIUS generates the method blocks.

## Standards And Dictionaries

- RFC 4186: EAP-SIM
- RFC 4187: EAP-AKA
- RFC 5448: EAP-AKA-prime
- RFC 3748: EAP base protocol
- RFC 2865 and RFC 5080: RADIUS packet behavior and `Message-Authenticator`
- FreeRADIUS modules: `rlm_eap_sim`, `rlm_eap_aka`, `rlm_eap_aka_prime`
- FreeRADIUS dictionaries commonly involved: `dictionary.3gpp`,
  `dictionary.3gpp2`, `dictionary.wimax`, Ericsson and Starent carrier
  dictionaries, and the standard RADIUS dictionary.

## Engineering Scope

Software implementation is complete for:

- typed `radius.eap.sim_aka` configuration
- strict validation for enabled methods, vector provider references, vector
  freshness, SIM triplet counts, AKA quintuplet counts, AKA-prime network name,
  KDF policy, pseudonym privacy, resync windows, and retention limits
- EAP framework catalog promotion from planned to complete for `sim`, `aka`,
  and `aka-prime`
- deterministic policy evaluation for accepted, rejected, and monitor-allowed
  SIM/AKA decisions
- FreeRADIUS `mods-enabled/eap` generation for `sim`, `aka`, and `aka_prime`
  only when policy is healthy
- bounded `eap_sim_aka_events` telemetry with hashed subscriber identifiers
- admin API, OpenAPI, RBAC, production readiness, system status, support bundle,
  Access Settings, and Dashboard visibility
- automated Go tests and CI target `make test-eap-sim-aka`

## Configuration

```yaml
radius:
  eap:
    sim_aka:
      enabled: true
      methods: ["sim", "aka", "aka-prime"]
      require_identity: true
      require_permanent_identity: true
      allow_pseudonym_identity: true
      require_pseudonym_reauth: false
      pseudonym_ttl_seconds: 86400
      reauth_ttl_seconds: 43200
      vector_provider: external-http
      vector_provider_ref: env:AEGIS_SIMAKA_VECTOR_PROVIDER_URL
      require_fresh_vectors: true
      max_vector_age_seconds: 300
      min_triplets: 2
      min_quintuplets: 1
      allow_resynchronization: true
      resync_window_seconds: 300
      require_network_name: true
      network_name: wlan.mnc001.mcc001.3gppnetwork.org
      require_kdf: true
      fail_on_provider_unavailable: true
      event_retention_limit: 6000
    framework:
      enabled: true
      mode: enforce
      fail_closed: true
      allowed_methods: ["peap", "ttls", "tls", "sim", "aka", "aka-prime"]
      require_message_authenticator: true
      require_identity_binding: true
```

Keep SIM/AKA methods out of `allowed_methods` until a vector provider reference
and the external validation checklist are ready.

## APIs

```text
GET  /api/v1/system/eap-framework/sim-aka
POST /api/v1/system/eap-framework/sim-aka/evaluate
```

The evaluate endpoint accepts method facts including identities, vector
provider availability, vector freshness, triplet or quintuplet counts, SRES/RES,
MAC, AUTN, AUTS, AKA-prime network name, KDF status, replay state, and optional
audit recording.

## Stored State

`eap_sim_aka_events` stores recent decisions with:

- hashed identity, permanent identity, pseudonym identity, reauth identity,
  network name, and calling-station ID
- vector provider availability and freshness
- triplet and quintuplet counts
- RES, MAC, AUTN, AUTS, KDF, resync, and replay evidence
- policy mode, reason, NAS identifier, NAS type, latency, and redacted details

## Operational Rules

- Enforce mode requires `Message-Authenticator`, identity binding, fresh
  vectors, and a configured vector provider reference.
- EAP-SIM requires at least two GSM triplets.
- EAP-AKA and EAP-AKA-prime require at least one AKA quintuplet.
- EAP-AKA-prime requires network-name binding and KDF validation.
- Raw IMSI, pseudonym, and reauth identities must not be stored in operational
  history; use hashes from the API and support bundle evidence.

## Release Certification

Software implementation is complete. External carrier, FreeRADIUS production
Linux, HSS/HLR/UDM, AP/controller, HA, performance, security, and customer
validation evidence is tracked separately in
`nas-0025-release-certification-checklist.md`.
