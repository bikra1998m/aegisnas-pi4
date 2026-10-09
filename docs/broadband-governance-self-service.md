# Broadband Lawful Governance And Subscriber Self-Service

NAS-0091 implements the software lifecycle for legally governed
lawful-intercept control, dual-approval evidence, subscriber self-service, and
privacy controls. It ties subscriber state, commercial catalog, quota/balance,
SQL accounting, accounting service correlation, dynamic authorization,
administrator MFA, and administrator WebAuthn into one auditable preview/apply
workflow.

## Scope

Software completion includes:

- `broadband.governance_self_service` configuration and validation
- dependency checks for subscriber state, commercial catalog, quota/balance,
  SQL accounting, accounting services, dynamic authorization, MFA, and WebAuthn
- lawful-intercept case intent with case id, authority, subscriber scope,
  tenant, adapter, retention class, approvers, and audit tags
- dual-approval policy intent with minimum approval count, MFA/WebAuthn
  requirements, allowed roles, break-glass policy, and escalation recipients
- subscriber self-service action intent for balance, plan change, top-up, usage
  export, privacy request, support ticket, and service cancellation workflows
- privacy policy intent for purpose, data class, retention, redaction,
  exportability, and subscriber notice
- compiled standards and vendor evidence for `Class`, `Filter-Id`,
  `Chargeable-User-Identity`, `Acct-Interim-Interval`, `Cisco-AVPair`,
  `Juniper-AV-Pair`, `Huawei-AVpair`, and `Nokia-AVPair`
- preview/apply APIs and RBAC
- durable event, lawful case, and self-service request tables
- runtime status, support bundle, OpenAPI, production readiness, UI, CI, and
  automated tests

External certification remains outside software completion and is tracked in
`nas-0091-release-certification-checklist.md`.

## Configuration

The feature is configured under `broadband.governance_self_service`.

Key fields:

- `enabled`: activates preview/apply governance
- `mode`: `monitor` or `enforce`
- `require_subscriber_state`: requires subscriber lifecycle state
- `require_commercial_catalog`: requires active product and subscription model
- `require_quota_balance`: requires quota and wallet lifecycle evidence
- `require_accounting`: requires SQL accounting and service correlation
- `require_dynamic_auth`: requires CoA/Disconnect for governed changes
- `require_mfa`: requires administrator MFA for governed approvals
- `require_admin_webauthn`: requires passkeys for high-risk approvals
- `lawful_intercept_enabled`: compiles lawful case evidence
- `self_service_enabled`: compiles subscriber self-service evidence
- `privacy_controls_enabled`: compiles privacy/redaction evidence
- `immutable_audit_required`: requires durable event evidence
- `dual_approval_required`: requires enabled approval policy evidence
- `cases`: scoped lawful-intercept case declarations
- `approval_policies`: dual-control approval rules
- `self_service_actions`: subscriber-visible action declarations
- `privacy_policies`: retention, redaction, and notice declarations

Use monitor mode until preview output, support bundle evidence, compliance
ownership, and customer legal process agree with the target environment.

## APIs

```text
GET  /api/v1/system/broadband-governance-self-service
POST /api/v1/system/broadband-governance-self-service/preview
POST /api/v1/system/broadband-governance-self-service/apply
GET  /api/v1/system/broadband-governance-self-service/history
```

Read-only, guest-admin, ops-admin, and super-admin users may read, preview, and
list history. Only ops-admin and super-admin users may apply.

## Persistence

NAS-0091 adds:

- `broadband_governance_self_service_events`
- `broadband_governance_cases`
- `broadband_self_service_requests`

Events store preview/apply evidence, plan fingerprints, mode, lawful case,
self-service action, privacy policy, approval policy, compliance, warning,
blocker, external requirement, and compiled attribute counts. Effective case
and self-service rows store the current software intent and source event for
support bundles and readiness evidence.

## Vendor Behavior

The normalized model compiles standards evidence for subscriber and legal
governance correlation. Vendor pack evidence adds:

- `Cisco-AVPair` for Cisco-family governance correlation
- `Juniper-AV-Pair` for Juniper/ERX governance correlation
- `Huawei-AVpair` for Huawei/H3C governance correlation
- `Nokia-AVPair` for Nokia/Alcatel-Lucent governance correlation
- `Class`, `Filter-Id`, and `Chargeable-User-Identity` for portable
  correlation across RADIUS authorization and accounting

Physical lawful-intercept adapters, regulator acceptance, and exact
vendor-product behavior remain release certification items instead of silent
software claims.

## Operations

Preview first:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-governance-self-service/preview \
  | jq '.report.status, .report.summary, .report.cases, .report.self_service_actions'
```

Apply after review:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-governance-self-service/apply \
  | jq '.result.status, .event_id'
```

Collect evidence with:

- `/api/v1/system/broadband-governance-self-service/history`
- support bundle file `api/broadband-governance-self-service.json`
- support bundle file `api/broadband-governance-self-service-history.json`
- production readiness key `broadband_governance_self_service`

## Production Boundary

Engineering is complete when code, validation, tests, docs, API/UI, migration,
runtime status, and evidence are implemented and passing. Court-order workflow
proof, regulator/customer acceptance, physical lawful-intercept adapters,
FreeRADIUS production Linux interop, HA failover, scale, soak, security audit,
production deployment, and customer acceptance are release certification tasks.
