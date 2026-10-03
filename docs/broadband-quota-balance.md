# Broadband Quota And Balance Lifecycle

NAS-0085 implements the software lifecycle for quota, balance, top-up,
prepaid, and postpaid broadband subscriber control. The feature records
production evidence for wallet state, quota profiles, top-up grants, rating
rules, reset policies, RADIUS authorization bindings, accounting correlation,
and CoA-on-exhaustion behavior.

## Scope

Software implementation is complete when AegisNAS can validate configuration,
preview the effective policy, persist normalized evidence, expose REST APIs,
show the state in Access Settings, and include the feature in production
readiness, support bundles, OpenAPI, CI, and automated tests.

Release certification remains separate. Live payment gateways, BSS/OSS wallet
sync, vendor BRAS/BNG packet proof, FreeRADIUS production Linux proof, HA
drills, scale/soak, security audit, production rollout, and customer acceptance
are tracked in `nas-0085-release-certification-checklist.md`.

## Configuration

Configure the feature under `broadband.quota_balance`. It depends on the
broadband subscriber state machine and, when enabled with production gates,
the commercial catalog, SQL accounting, accounting services, accounting
charging/rating, and Dynamic Authorization.

```yaml
broadband:
  quota_balance:
    enabled: true
    mode: "enforce"
    fail_closed: true
    default_currency: "USD"
    default_quota_period: "monthly"
    require_commercial_catalog: true
    require_active_wallet: true
    require_quota_profile: true
    rating_enabled: true
    top_up_enabled: true
    prepaid_enabled: true
    postpaid_enabled: true
    accounting_correlation_required: true
    auto_suspend_on_exhaustion: true
    coa_on_exhaustion: true
    wallets:
      - wallet_id: "wallet-lab-1"
        account_id: "acct-lab-1"
        subscription_id: "sub-commercial-1"
        subscriber_id: "sub-lab-cpe-01"
        username: "lab-cpe-01@example.net"
        billing_mode: "prepaid"
        status: "active"
        currency: "USD"
        balance_micros: 25000000
        quota_profile: "monthly-500g"
    quota_profiles:
      - name: "monthly-500g"
        enabled: true
        period: "monthly"
        included_total_octets: 536870912000
        warning_threshold_percent: 80
        hard_limit: true
        throttle_profile: "shape-10m"
        exhausted_role: "quota-exhausted"
        reset_policy: "monthly-reset"
    rating_rules:
      - name: "fiber-100m-overage"
        enabled: true
        plan: "fiber-100m"
        quota_profile: "monthly-500g"
        unit: "total-octets"
        price_micros: 25000
        rounding: "up"
    reset_policies:
      - name: "monthly-reset"
        enabled: true
        period: "monthly"
        reset_day: 1
        reset_hour: 3
```

## API

```text
GET  /api/v1/system/broadband-quota-balance
POST /api/v1/system/broadband-quota-balance/preview
POST /api/v1/system/broadband-quota-balance/apply
GET  /api/v1/system/broadband-quota-balance/history
```

Read-only roles may read, preview, and list history. Apply requires an
operator role. A blocked apply returns HTTP 409 with the full report.

## Evidence

Apply upserts these normalized tables:

- `broadband_quota_wallets`
- `broadband_quota_profiles`
- `broadband_topup_grants`
- `broadband_quota_rating_rules`
- `broadband_quota_reset_policies`
- `broadband_quota_balance_events`

Support bundles include `api/broadband-quota-balance.json` and
`api/broadband-quota-balance-history.json`.

## RADIUS Surfaces

Authorization evidence covers `Class`, `Filter-Id`, `Session-Timeout`,
`Idle-Timeout`, ChilliSpot quota attributes, Nomadix bandwidth attributes,
MikroTik rate limits, Cisco AVPair, Huawei rate attributes, CoA-Request, and
Disconnect-Request.

Accounting evidence covers `Acct-Status-Type`, `Acct-Session-Id`,
`Acct-Input-Octets`, `Acct-Output-Octets`, `Acct-Input-Gigawords`,
`Acct-Output-Gigawords`, `Acct-Session-Time`, and identity attributes used to
correlate wallet and quota state.
