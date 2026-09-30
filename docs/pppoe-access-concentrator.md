# PPPoE Access Concentrator Lifecycle

NAS-0082 adds the software lifecycle for a PPPoE access concentrator in AegisNAS. The lifecycle governs discovery/session intent, RADIUS authentication and accounting bindings, subscriber profile policy, dual-stack addressing, route and QoS intent, NAT/translation linkage, CoA/Disconnect readiness, history, and support evidence.

## Scope

Engineering scope:

- RFC 2516 PPPoE discovery frame parser and serializer with bounded tag validation.
- `broadband.pppoe` configuration with disabled-by-default operation.
- Enforce-mode validation for access interfaces, subscriber profiles, RADIUS shared secret, SQL accounting, accounting service correlation, session ownership, CoA, route policy, address policy, and translation policy.
- Lifecycle preview/apply APIs with event history in `pppoe_access_lifecycle_events`.
- Production readiness, system status, OpenAPI, support bundle, admin UI, and CI coverage.

Release certification scope:

- Live PPPoE session termination on physical NICs.
- DSLAM/OLT/ONT/access-node interoperability.
- Cisco, Juniper ERX, Huawei, Nokia/ALU, MikroTik, H3C, and ZTE device smoke tests.
- Packet-capture proof for PADI/PADO/PADR/PADS/PADT, PPP LCP, PAP/CHAP, IPCP, IPv6CP, accounting, CoA, and Disconnect.
- HA failover, throughput, scale, soak, security audit, production deployment, and customer acceptance.

## Configuration

`broadband.pppoe.enabled` defaults to `false`. Use `monitor` while reviewing the plan and evidence. Use `enforce` only when the backing policies are ready:

- `radius.sql_accounting.enabled`
- `radius.accounting_services.enabled`
- `radius.dynamic_auth.enabled`
- `radius.address_policy.enabled`
- `radius.route_policy.enabled`
- `radius.translation_policy.enabled` when NAT is required

Profiles map a subscriber role to pools and services:

```yaml
broadband:
  pppoe:
    enabled: true
    mode: monitor
    access_concentrator_name: aegisnas-bng-01
    service_name: internet
    interfaces:
      - name: eth1.100
        enabled: true
        vlan: 100
    profiles:
      - name: residential
        enabled: true
        role: residential
        address_pool: pppoe-v4
        ipv6_pool: pppoe-v6
        delegated_ipv6_pool: pppoe-pd
        route_policy: residential
        qos_profile: silver
        translation_pool: cgnat-pool
        service_chain: retail-internet
        vendor_packs: [mikrotik, alcatel-lucent-service-router, huawei]
```

## API

```text
GET  /api/v1/system/pppoe-access-lifecycle
POST /api/v1/system/pppoe-access-lifecycle/preview
POST /api/v1/system/pppoe-access-lifecycle/apply
GET  /api/v1/system/pppoe-access-lifecycle/history
```

Preview records evidence without changing live access interfaces. Apply records a lifecycle checkpoint and runtime status. Live data-plane activation stays gated by release certification.

## Evidence

Status appears under `/api/v1/system/status` as `radius.pppoe_access_lifecycle` and production readiness as `pppoe_access_lifecycle`.

Support bundles include:

- `api/pppoe-access-lifecycle.json`
- `api/pppoe-access-lifecycle-history.json`

## Testing

Automated coverage:

- `go test ./internal/broadband/pppoe`
- `go test ./internal/config -run BroadbandPPPoEAccessLifecycle`
- `go test ./internal/enforcement -run PPPoEAccessLifecycle`
- `go test -timeout=600s ./internal/db -run 'PPPoEAccess|Migrate'`
- `go test ./internal/adminapi -run PPPoEAccessLifecycle`
- `cd web/admin-ui && npm run build`

Run all focused checks with:

```bash
make test-pppoe-access-lifecycle
```
