# WiMAX Subscriber And Service-Flow Support

NAS-0096 adds the software lifecycle for WiMAX subscriber profiles, service-flow authorization, ASN mobility, charging correlation, and WiMAX RADIUS VSA evidence.

## Scope

The implementation provides:

- `mobile.wimax` configuration with monitor/enforce modes, fail-closed controls, privacy controls, retention limits, dependency gates, subscriber profiles, service flows, ASN profiles, and mobility policies.
- Deterministic preview/apply reports at `/api/v1/system/wimax-service-flows`.
- Durable schema v100 history in `wimax_service_flow_events` and `wimax_service_flow_profiles`.
- Runtime status, production readiness, system status, support bundle captures, OpenAPI, RBAC, and Access Settings UI coverage.
- Automated unit, DB, enforcement, API, and browser tests.

## Attribute Families

The software model exposes WiMAX intent through attributes including:

- `WiMAX-MN-NAI`
- `WiMAX-Session-Id`
- `WiMAX-Service-Flow-ID`
- `WiMAX-QoS-Descriptor`
- `WiMAX-Packet-Flow-Descriptor`
- `WiMAX-Accounting-Capabilities`
- `Filter-Id`
- `Class`
- `Session-Timeout`
- `Acct-Interim-Interval`

Grouped packet encoding remains owned by NAS-0092. Charging correlation remains owned by NAS-0094. NAS-0096 ties those capabilities into WiMAX subscriber, service-flow, ASN, and mobility evidence.

## Operator Flow

1. Configure `mobile.wimax` in monitor mode and review defaults.
2. Call `POST /api/v1/system/wimax-service-flows/preview`.
3. Review subscriber profiles, service flows, ASN profiles, mobility policies, compliance checks, blockers, warnings, and the plan fingerprint.
4. Call `POST /api/v1/system/wimax-service-flows/apply` after review.
5. Export the support bundle and keep `api/wimax-service-flows.json` plus `api/wimax-service-flows-history.json` with release evidence.
6. Track live ASN gateway, base-station, CPE, RF lab, FreeRADIUS production Linux, HA, scale, soak, security, and customer proof in `nas-0096-release-certification-checklist.md`.

## Production Notes

Software completion is not blocked by external WiMAX hardware. A production release still needs exact vendor/product/firmware scope, packet captures, real accounting/CoA behavior, HA failover proof, load/soak evidence, security review, and customer acceptance evidence.
