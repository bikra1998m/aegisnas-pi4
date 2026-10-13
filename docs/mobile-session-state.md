# Mobile Session, APN, And Bearer State

NAS-0093 adds the software lifecycle for mobile APN, PDP/PDN, bearer,
roaming, and handover state. It builds on NAS-0092 grouped telecom AVP support
and keeps carrier equipment proof as release certification evidence.

## Scope

The feature models:

- APN profiles with PDN type, IPv4 pool, IPv6 prefix pool, QoS, charging,
  policy, default bearer, roaming posture, lawful retention group, and RADIUS
  attribute evidence.
- Default and dedicated bearer templates with QCI, ARP, bandwidth ceilings,
  traffic-flow templates, preemption posture, and RADIUS attribute evidence.
- Roaming partners with realm, MCC/MNC, visited/home policy, local breakout,
  allowed APNs, and RADIUS attribute evidence.
- Session state transitions for attach, PDP context creation, default bearer,
  dedicated bearer, roaming or handover, and detach.
- Preview/apply history, effective APN/bearer/roaming rows, runtime status,
  system status, production readiness, OpenAPI, support bundles, and Admin UI
  evidence.

The software implementation is complete when code, schema, APIs, UI,
configuration, documentation, and automated tests are present. Carrier
packet-core simulators, real Starent/Cisco/Ericsson/3GPP devices, production
FreeRADIUS Linux captures, HA validation, scale, soak, security audit, and
customer acceptance are tracked in
`docs/nas-0093-release-certification-checklist.md`.

## Standards And Dictionaries

- RFC 2865, RFC 2866, RFC 5176
- 3GPP TS 23.401, 3GPP TS 29.061, 3GPP TS 32.240
- FreeRADIUS `dictionary.3gpp`, `dictionary.starent`, and Ericsson packet-core
  dictionaries
- Attributes include `3GPP-IMSI`, `3GPP-IMEISV`, `3GPP-Charging-ID`,
  `3GPP-RAT-Type`, `3GPP-Selection-Mode`,
  `3GPP-GPRS-Negotiated-QoS-profile`, `3GPP-Negotiated-DSCP`,
  `Framed-IP-Address`, `Framed-IPv6-Prefix`, `Acct-Interim-Interval`,
  `Filter-Id`, `Session-Timeout`, and `Class`.

## Configuration

```yaml
mobile:
  grouped_avps:
    enabled: true
    mode: enforce
    safe_raw_evidence: true
    hash_raw_values: true
  sessions:
    enabled: true
    mode: enforce
    fail_closed: true
    require_database: true
    require_grouped_avps: true
    require_accounting: true
    require_dynamic_auth: true
    state_reconciliation: true
    handover_tracking: true
    roaming_tracking: true
    redact_subscriber_ids: true
    hash_subscriber_ids: true
    default_apn: internet
    default_pdn_type: ipv4v6
```

`lite` deployments may run monitor mode only. Enforce mode requires at least
one enabled APN profile, one enabled bearer template, grouped AVP support, and
hashed subscriber correlation whenever subscriber redaction is active.

## Operator Workflow

Preview:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/mobile-sessions/preview \
  | jq '.report.status, .report.summary, .report.apn_profiles'
```

Apply:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/mobile-sessions/apply \
  | jq '.result.status, .event_id'
```

History:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/mobile-sessions/history?limit=20' \
  | jq '.summary, .effective_state'
```

Read-only roles may read, preview, and list history. `ops_admin` and
`super_admin` may apply. A blocked apply returns HTTP 409 with the complete
report.

## Persistence

Schema v97 adds:

- `mobile_session_state_events`
- `mobile_session_state_profiles`

`mobile_session_state_events` records preview/apply evidence, plan fingerprint,
compiled counts, compliance counts, and report JSON. `mobile_session_state_profiles`
stores effective APN, bearer, and roaming rows keyed by profile type and name.

## Monitoring And Support

Production readiness reports the feature as `mobile_session_state`.
System status exposes the same state under the RADIUS and enforcement maps.
Support bundles include:

- `api/mobile-sessions.json`
- `api/mobile-sessions-history.json`

Runtime status uses component `mobile_session_state`.

## High Availability

The feature is HA-friendly because preview/apply evidence and effective rows
are stored in the database. Standby nodes can replay the latest effective APN,
bearer, and roaming profiles by reading `mobile_session_state_profiles` and
matching the latest `plan_fingerprint`.
