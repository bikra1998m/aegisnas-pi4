# Mobile Online/Offline Charging Correlation

NAS-0094 adds the software lifecycle for mobile online charging, offline CDR
charging, rating-group mapping, quota policy, and mediation correlation. It
builds on NAS-0041 accounting charging records and NAS-0093 mobile session
state. Live OCS/OFCS settlement, packet-core hardware, and customer acceptance
remain release certification evidence.

## Scope

The feature models:

- Charging streams for online OCS, offline OFCS, and mediation handoff.
- Rating groups that bind APNs, service identifiers, units, currency, and
  quota policy references.
- Quota policies with grant units, initial grants, threshold handling,
  validity windows, exhaustion behavior, and CoA action intent.
- CDR/export correlation from NAS-0041 accounting charging evidence.
- Subscriber privacy controls for redaction and deterministic hashing.
- Preview/apply history, effective stream/rating/quota rows, runtime status,
  system status, production readiness, OpenAPI, support bundles, and Admin UI
  evidence.

The software implementation is complete when code, schema, APIs, UI,
configuration, documentation, automation, and automated tests pass. Live OCS,
OFCS, carrier packet-core simulators, real Starent/Cisco/Ericsson/3GPP/3GPP2
devices, production FreeRADIUS Linux captures, HA validation, scale, soak,
security audit, and customer acceptance are tracked in
`docs/nas-0094-release-certification-checklist.md`.

## Standards And Dictionaries

- RFC 2865, RFC 2866, RFC 5176, RFC 6929
- 3GPP TS 29.061 and 3GPP TS 32.240
- 3GPP2 X.S0011
- FreeRADIUS `dictionary.3gpp`, `dictionary.3gpp2`,
  `dictionary.starent`, Ericsson packet-core dictionaries, and
  `dictionary.wimax`
- Attributes include `3GPP-IMSI`, `3GPP-IMEISV`,
  `3GPP-IMSI-MCC-MNC`, `3GPP-Charging-ID`,
  `3GPP-Charging-Characteristics`, `3GPP2-Prepaid-Quota-Identifier`,
  `WiMAX-Session-Id`, `Chargeable-User-Identity`, `Class`,
  `Acct-Session-Id`, `Acct-Status-Type`, `Acct-Input-Octets`,
  `Acct-Output-Octets`, `Acct-Input-Gigawords`, `Acct-Output-Gigawords`,
  and `Event-Timestamp`.

## Configuration

```yaml
mobile:
  sessions:
    enabled: true
    mode: enforce
  charging:
    enabled: true
    mode: enforce
    fail_closed: true
    require_database: true
    require_mobile_sessions: true
    require_accounting_charging: true
    quota_correlation: true
    require_mediation: true
    redact_subscriber_ids: true
    hash_subscriber_ids: true
    default_currency: USD
    streams:
      - name: ocs-online
        enabled: true
        stream_type: online
        protocol: radius-accounting
        endpoint_ref: ocs-primary
        export_format: jsonl
      - name: ofcs-offline
        enabled: true
        stream_type: offline
        protocol: radius-accounting
        endpoint_ref: ofcs-primary
        export_format: jsonl
    rating_groups:
      - name: internet-data
        enabled: true
        apn: internet
        service_id: 1001
        rating_group: 10
        unit_type: octets
        currency: USD
        quota_policy: default-data-quota
    quota_policies:
      - name: default-data-quota
        enabled: true
        grant_unit: octets
        initial_grant: 1073741824
        threshold_percent: 80
        validity_seconds: 3600
        exhaustion_action: restrict
        coa_profile: mobile-quota-throttle
```

Enforce mode requires a database, mobile session state, NAS-0041 accounting
charging, at least one online stream, at least one offline stream, at least one
rating group, at least one quota policy, and hashed subscriber correlation when
subscriber redaction is active. Lite deployments may use monitor mode only.

## Operator Workflow

Preview:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/mobile-charging/preview \
  | jq '.report.status, .report.summary, .report.streams'
```

Apply:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/mobile-charging/apply \
  | jq '.result.status, .event_id'
```

History:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/mobile-charging/history?limit=20' \
  | jq '.summary, .profiles'
```

Read-only roles may read, preview, and list history. `ops_admin` and
`super_admin` may apply. A blocked apply returns HTTP 409 with the complete
report.

## Persistence

Schema v98 adds:

- `mobile_charging_correlation_events`
- `mobile_charging_correlation_profiles`

`mobile_charging_correlation_events` records preview/apply evidence, plan
fingerprint, stream/rating/quota counts, compliance counts, summary JSON, and
report JSON. `mobile_charging_correlation_profiles` stores effective stream,
rating-group, and quota-policy rows keyed by profile type and name.

## Monitoring And Support

Production readiness reports the feature as `mobile_charging_correlation`.
System status exposes the same state under the RADIUS and enforcement maps.
Support bundles include:

- `api/mobile-charging.json`
- `api/mobile-charging-history.json`

Runtime status uses component `mobile_charging_correlation`.

## High Availability

The feature is HA-friendly because preview/apply evidence and effective rows
are stored in the database. Standby nodes can replay the latest effective
stream, rating-group, and quota-policy rows by reading
`mobile_charging_correlation_profiles` and matching the latest
`plan_fingerprint`.
