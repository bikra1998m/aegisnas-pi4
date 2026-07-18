# Machine And User Authentication Correlation

NAS-0026 adds a production software layer for correlating managed-machine
authentication with user authentication. TEAP proves that both identities can be
carried safely inside an EAP conversation; this feature decides whether those
identities are allowed to become one authorization context.

## Problem

Enterprise Windows, switch, and WLAN deployments often authenticate a device at
boot, then authenticate the user after logon. Without correlation, a server can
grant user access from an unmanaged or stale machine context, or apply a machine
role after a user policy should take precedence.

The feature supports:

- machine-then-user correlation
- same-session correlation
- machine-only, user-only, and migration `either` modes
- fresh machine-authentication TTLs
- same `Calling-Station-Id` and optional same NAS binding
- deterministic role merge
- conflict rejection, monitoring, or quarantine
- bounded event history and current correlation state

## Vendor And Standards Scope

Vendors and products that implement comparable workflows include Microsoft NPS,
Cisco ISE, Aruba ClearPass, HP/Aruba switching and WLAN products, and managed
Windows supplicants.

Relevant standards and dictionaries:

- RFC 3748 for EAP
- RFC 2865 for RADIUS authentication attributes
- RFC 5176 for later CoA or Disconnect enforcement
- RFC 7170 for TEAP method chaining
- FreeRADIUS TEAP TLVs:
  `FreeRADIUS-EAP-TEAP-Identity-Type`,
  `FreeRADIUS-EAP-TEAP-EAP-Payload`,
  `FreeRADIUS-EAP-TEAP-Crypto-Binding`, and
  `FreeRADIUS-EAP-TEAP-Result`
- standard attributes: `User-Name`, `Calling-Station-Id`, `NAS-Identifier`,
  `State`, `Class`, `Filter-Id`, and VLAN tunnel attributes

## Configuration

```yaml
radius:
  eap:
    framework:
      enabled: true
      mode: enforce
      fail_closed: true
      allowed_methods: ["peap", "ttls", "tls", "teap"]
      require_message_authenticator: true
      require_identity_binding: true
    teap:
      enabled: true
      require_crypto_binding: true
      require_identity_type: true
      require_machine_identity: true
      require_user_identity: true
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
      require_same_nas: false
      require_fresh_machine_auth: true
      machine_auth_ttl_seconds: 28800
      user_auth_ttl_seconds: 28800
      transition_window_seconds: 900
      allowed_machine_methods: ["teap", "tls"]
      allowed_user_methods: ["teap", "peap", "ttls"]
      identity_precedence: user_over_machine
      role_merge_strategy: user_primary
      conflict_action: reject
      stale_machine_action: reject
      machine_identity_prefixes: ["host/", "machine/"]
      audit_enabled: true
      event_retention_limit: 6000
```

Use monitor mode while introducing a new supplicant profile or migration SSID.
Use enforce mode only when TEAP generation, cryptobinding, same-client binding,
and machine/user transition evidence are clean.

## API

```text
GET  /api/v1/system/eap-framework/machine-user
POST /api/v1/system/eap-framework/machine-user/evaluate
```

The `GET` response includes the effective policy, capability catalog, current
hashed correlation state, runtime summary, recent audited decisions, blockers,
warnings, and release certification checklist name.

The `evaluate` endpoint accepts machine/user facts such as machine identity,
user identity, methods, authentication ages, `Calling-Station-Id`,
`NAS-Identifier`, TEAP evidence, roles, posture, and an optional `audit` flag.
When telemetry and `audit_enabled` are true, AegisNAS stores hashed evidence.

## Stored State

`eap_machine_user_correlations` stores append-only correlation decisions.

`eap_machine_user_session_state` stores the current bounded state by a stable
correlation key.

Both tables store hashes for identities and calling-station values. Raw machine
names, usernames, MAC addresses, and outer identities are not persisted.

## Operational Rules

- Keep `require_same_calling_station: true` for production.
- Keep `require_fresh_machine_auth: true` and set a bounded machine TTL.
- Use `role_merge_strategy: user_primary` for normal employee access.
- Use `deny_conflict` or `conflict_action: quarantine` for sensitive zones.
- Treat monitor decisions as evidence, not authorization success.
- Retain `api/eap-framework-machine-user.json` from support bundles.

## Software Completion

Software implementation is complete when config validation, evaluator logic,
database migrations, REST APIs, RBAC, OpenAPI, support bundles, dashboard,
Access Settings, production-readiness checks, automated tests, CI target, and
documentation pass.

External validation remains in
[nas-0026-release-certification-checklist.md](nas-0026-release-certification-checklist.md).
