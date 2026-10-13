# Mobile Policy Control

NAS-0095 adds the software lifecycle for PCRF/PCF-style mobile policy control. It compiles mobile session state, APN intent, QoS class, roaming policy, charging feedback, and dynamic authorization requirements into auditable RADIUS policy evidence.

## Scope

Software implementation is complete when:

- `mobile.policy_control` validates policy profiles, QoS classes, roaming policies, and feedback rules.
- `/api/v1/system/mobile-policy-control` exposes the effective report, compliance checks, release boundary, and durable evidence.
- Preview and apply operations persist `mobile_policy_control_events` and `mobile_policy_control_profiles`.
- Production readiness, system status, support bundles, OpenAPI, and the admin UI expose the same effective state.

External release evidence remains outside software completion and is tracked in `nas-0095-release-certification-checklist.md`.

## Standards And Vendor Families

The feature models RADIUS-facing policy behavior from RFC 2865, RFC 2866, RFC 5176, RFC 6929, 3GPP TS 23.203, 3GPP TS 23.401, 3GPP TS 29.212, 3GPP TS 29.214, and 3GPP TS 29.512. Vendor scopes include 3GPP PCRF/PCF, Starent/Cisco ASR, Ericsson/Redback, Ericsson packet core, WiMAX ASN gateways, and Diameter Gx/Rx/Npcf policy systems.

## Configuration

Enable policy control under `mobile.policy_control`:

```yaml
mobile:
  policy_control:
    enabled: true
    mode: enforce
    fail_closed: true
    require_database: true
    require_mobile_sessions: true
    require_policy_engine: true
    require_qos: true
    require_dynamic_auth: true
    require_charging: true
    roaming_control: true
    enforcement_feedback: true
    redact_subscriber_ids: true
    hash_subscriber_ids: true
```

In enforce mode, the runtime requires mobile sessions, mobile charging, typed policy engine, QoS enforcement through runtime shaping or broadband QoS service flows, dynamic authorization, privacy hashing, and durable database history.

## Operator Flow

1. Configure mobile session, charging, policy engine, QoS, and dynamic authorization prerequisites.
2. Run `POST /api/v1/system/mobile-policy-control/preview`.
3. Review policy profiles, QoS classes, roaming policies, feedback rules, compliance checks, and the plan fingerprint.
4. Run `POST /api/v1/system/mobile-policy-control/apply`.
5. Archive `/api/v1/system/mobile-policy-control/history` and the support bundle evidence before release certification.

## Persistence

Schema v99 adds:

- `mobile_policy_control_events`
- `mobile_policy_control_profiles`

The tables preserve preview/apply events, effective policy rows, QoS classes, roaming policy rows, feedback rules, compliance counts, actors, and plan fingerprints for HA replay and audit.

## Release Boundary

Software readiness does not require live PCRF/PCF/PCEF, roaming clearinghouse, carrier packet-core hardware, production FreeRADIUS captures, HA drills, scale tests, soak tests, security audits, or customer acceptance. Those activities are release certification tasks.
