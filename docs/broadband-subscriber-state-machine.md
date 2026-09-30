# Broadband Subscriber State Machine

NAS-0083 defines the production software lifecycle for broadband subscribers
after access admission. It turns PPPoE, RADIUS authorization, SQL accounting,
service-chain policy, address/route/QoS/NAT ownership, CoA, reconnect recovery,
and support evidence into a deterministic state model.

## Scope

The engineering implementation is complete when the software can:

- validate `broadband.subscriber_state` configuration with fail-closed defaults;
- expose canonical states and transitions from discovery to accounting stop;
- model subscriber products, service legs, failure policies, reconnect recovery,
  and accounting correlation;
- persist preview/apply evidence and runtime status;
- report readiness through API, system status, production readiness, support
  bundles, CI, and the admin UI.

Live BRAS/BNG behavior, packet captures, billing mediation, wholesale handoff,
HA failover, scale, soak, security audit, production deployment, and customer
acceptance remain release certification tasks tracked separately in
`nas-0083-release-certification-checklist.md`.

## Configuration

Enable the feature under `broadband.subscriber_state`. Use `mode: monitor` while
building catalog data and switch to `mode: enforce` only after preview evidence
is clean.

Important fields:

- `default_access_method`: `pppoe`, `ipoe`, `dhcp`, `l2tp`, or `static`.
- `products`: product-to-role bindings with address, route, QoS, translation,
  quota, service-chain, and vendor-pack intent.
- `service_policies`: product service-leg transitions with triggers such as
  `accounting-start`, `accounting-interim`, `quota-threshold`, `coa`,
  `reconnect`, and `accounting-stop`.
- `failure_policies`: deterministic fail-closed, recovery, suspension,
  disconnect, quarantine, or monitor behavior.
- `require_accounting_start`, `require_accounting_stop`, and
  `require_session_ownership`: gates for durable accounting and reconnect
  safety.
- `dual_stack_required`, `route_policy_required`, `qos_required`,
  `nat_required`, and `coa_required`: dependency gates into existing
  enforcement subsystems.

## State Model

The canonical model includes these states:

`new`, `discovered`, `authenticating`, `authorized`, `address_assigned`,
`service_active`, `accounting_started`, `interim_seen`,
`policy_update_pending`, `reconnecting`, `suspended`, `disconnecting`,
`stopped`, `recovered`, and `failed`.

Transitions are represented by typed events such as discovery, Access-Request,
Access-Accept, address assignment, service activation, Accounting Start,
Interim-Update, policy update, CoA ACK, reconnect, Accounting Stop, disconnect,
recovery scan, and failure. Invalid transitions fail closed in the state-machine
package.

## APIs

```text
GET  /api/v1/system/broadband-subscriber-state
POST /api/v1/system/broadband-subscriber-state/preview
POST /api/v1/system/broadband-subscriber-state/apply
GET  /api/v1/system/broadband-subscriber-state/history
```

Read-only, guest, ops, and super admins may read, preview, and list history.
Only ops and super admins may apply.

## Persistence

Schema version 87 adds:

- `broadband_subscribers`
- `broadband_subscriber_sessions`
- `broadband_subscriber_service_legs`
- `broadband_subscriber_state_events`

The event table stores preview/apply evidence, plan fingerprints, product and
service-policy counts, transition counts, compliance counts, actor, summary
JSON, full report JSON, and timestamps. Later product, quota, address, QoS,
route, and activation features build on these foundations.

## Operator Workflow

1. Configure dependencies: PPPoE access lifecycle, SQL accounting, accounting
   service correlation, dynamic authorization, address policy, route policy,
   optional translation policy, and HA settings.
2. Add subscriber products and service policies with `enabled: false`.
3. Preview with `/api/v1/system/broadband-subscriber-state/preview`.
4. Resolve blockers and warnings.
5. Enable product/service policies and switch to `mode: enforce`.
6. Apply with `/api/v1/system/broadband-subscriber-state/apply`.
7. Export a support bundle and preserve release evidence for exact vendor and
   firmware scope.

## Monitoring

The feature reports through:

- `/api/v1/system/status` under `radius.broadband_subscriber_state`;
- `/api/v1/system/production-readiness` as `broadband_subscriber_state`;
- runtime status component `broadband_subscriber_state`;
- support-bundle captures `api/broadband-subscriber-state.json` and
  `api/broadband-subscriber-state-history.json`;
- admin UI Access Settings section `Broadband Subscriber State Machine`.

## Security And HA

Enforce mode is blocked until accounting and session ownership are available for
fail-closed deployments. Reconnect recovery is bounded by
`reconnect_window_seconds` and `max_reconnects`, and apply operations record
runtime status for HA peers and support evidence. Live failover proof remains a
release certification item.
