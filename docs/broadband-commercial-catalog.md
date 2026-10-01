# Broadband Commercial Catalog

NAS-0084 implements the software lifecycle for commercial broadband accounts,
product plans, service bundles, subscriptions, and concurrent session policy.
It gives operators a durable catalog that can be validated before enforcement,
applied as an auditable checkpoint, exposed through REST APIs and the admin UI,
and correlated with subscriber state, accounting, and dynamic authorization.

## Scope

The software implementation covers:

- account hierarchy, tenant ownership, billing mode, family accounts, and
  account session/subscription limits
- product plans with recurring period, currency, price, subscriber product
  binding, service chain, address pools, route policy, QoS, NAT/translation,
  portal, grace, suspension, timeout, and vendor-pack hints
- service bundles with required and mutually exclusive plan rules,
  eligibility tags, priorities, and shared concurrency
- subscriptions that bind accounts to subscriber IDs or usernames, with active,
  suspended, grace, cancelled, expired, pending, and trial status handling
- concurrent session policies by global, tenant, account, subscriber, plan, or
  bundle scope, including burst, grace, reject, quarantine, suspend, and CoA
  actions
- authorization and accounting evidence for RADIUS Access-Accept and
  Accounting Start/Interim/Stop correlation
- production readiness, support-bundle capture, runtime status, event history,
  schema repair, admin API RBAC, and Access Settings UI operations

Live BSS/OSS billing systems, BRAS/BNG hardware, external FreeRADIUS Linux
captures, HA failover drills, performance/soak benchmarks, security audit, and
customer acceptance are release certification activities. They are tracked in
[nas-0084-release-certification-checklist.md](nas-0084-release-certification-checklist.md).

## Configuration

Configure the catalog under `broadband.commercial_catalog`. The catalog depends
on `broadband.subscriber_state.enabled`. Accounting correlation requires
`radius.sql_accounting.enabled` and `radius.accounting_services.enabled`.
Limit-triggered CoA requires `radius.dynamic_auth.enabled`.

Use `mode: monitor` while building evidence. Use `mode: enforce` only after the
preview report is ready and fail-closed policy is intentional.

```yaml
broadband:
  commercial_catalog:
    enabled: true
    mode: enforce
    fail_closed: true
    default_billing_period: monthly
    default_currency: USD
    allow_family_accounts: true
    require_active_subscription: true
    require_bundle_eligibility: true
    enforce_concurrency: true
    accounting_correlation_required: true
    coa_on_limit: true
    accounts:
      - account_id: acct-lab-1
        parent_account_id: acct-family-1
        tenant: retail
        status: active
        billing_mode: postpaid
        owner_name: Lab Family
        max_subscriptions: 4
        max_sessions: 8
    plans:
      - name: fiber-100m
        enabled: true
        product: residential-fiber
        billing_period: monthly
        price_micros: 49990000
        currency: USD
        max_sessions: 4
        downstream_kbps: 100000
        upstream_kbps: 25000
        qos_profile: silver
        vendor_packs: [standard, aegisnas, mikrotik, cisco]
    bundles:
      - name: family-fiber
        enabled: true
        plans: [fiber-100m]
        required_plans: [fiber-100m]
        shared_concurrency: true
        eligibility_tags: [family]
    subscriptions:
      - subscription_id: sub-lab-1
        account_id: acct-lab-1
        subscriber_id: subscriber-1001
        username: user@example.test
        plan: fiber-100m
        bundle: family-fiber
        status: active
        max_sessions: 4
    concurrency_policies:
      - name: family-fiber-limit
        enabled: true
        scope: bundle
        bundle: family-fiber
        max_sessions: 8
        max_sessions_per_subscriber: 4
        action: coa
        coa_action: disconnect-oldest
```

## API

```text
GET  /api/v1/system/broadband-commercial-catalog
POST /api/v1/system/broadband-commercial-catalog/preview
POST /api/v1/system/broadband-commercial-catalog/apply
GET  /api/v1/system/broadband-commercial-catalog/history
```

Read-only roles may read, preview, and list history. `ops_admin` and
`super_admin` may apply. Preview records an evidence event without mutating
catalog records. Apply records an auditable event, upserts normalized catalog
records, and updates runtime/integration history. A blocked apply returns HTTP
409 with the report.

## Operations

Preview before enforcement:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-commercial-catalog/preview \
  | jq '.report.status, .report.summary, .report.plans, .report.concurrency_policies'
```

Apply after reviewing the plan fingerprint, accounts, plans, bundles,
subscriptions, concurrency policies, RADIUS authorization/accounting bindings,
and compliance checks:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/broadband-commercial-catalog/apply \
  | jq '.result.status, .event_id'
```

Use `/api/v1/system/broadband-commercial-catalog/history` and support bundle
files `api/broadband-commercial-catalog.json` and
`api/broadband-commercial-catalog-history.json` during product, subscription,
concurrency, accounting, and CoA investigations.

## Persistence

Schema v89 adds:

- `broadband_commercial_accounts`
- `broadband_commercial_plans`
- `broadband_commercial_bundles`
- `broadband_commercial_subscriptions`
- `broadband_commercial_concurrency_policies`
- `broadband_commercial_catalog_events`

Catalog records are upserted by apply event ID. Event rows retain summary JSON,
report JSON, counts, status, fingerprint, actor, and timestamps for audit and
rollback evidence.

## Readiness

Software implementation is complete when:

- configuration validation blocks invalid catalog, plan, bundle, subscription,
  and concurrency states
- preview/apply API, RBAC, OpenAPI, readiness, status, and support bundles work
- catalog records and event history persist across migrations
- Access Settings displays the catalog and can preview/apply it
- automated unit, integration, migration, API, and browser tests pass

External certification must not block software roadmap closure.
