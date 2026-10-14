# NAS-0096 Release Certification Checklist

NAS-0096 software implementation is complete when code, database, APIs, UI, configuration, automated tests, documentation, and CI wiring pass. The items below are external release certification and do not block the next roadmap feature.

## Software Status

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes
- Feature ID: NAS-0096
- Feature: WiMAX subscriber and service-flow support

## External Certification

- IANA/vendor identity review for release artifacts.
- FreeRADIUS production Linux interoperability with WiMAX dictionaries and captured Access-Request, Access-Accept, Accounting, CoA, and Disconnect packets.
- WiMAX ASN gateway validation with configured subscriber profiles, service flows, ASN profiles, and mobility policies.
- Base-station and CPE smoke tests for service-flow assignment and reauthorization.
- Alvarion, WiChorus, Navini, and available WiMAX Forum-compatible device tests with exact product and firmware versions.
- RF lab validation for handover and reauthentication behavior.
- Charging correlation with live or certified OCS/OFCS mediation.
- HA failover and replay validation for `wimax_service_flow_events` and `wimax_service_flow_profiles`.
- Scale and soak testing for configured `max_subscribers`, event retention, and history export.
- Packet-capture evidence for malformed, unsupported, and policy-denied WiMAX attributes.
- Security review for subscriber identifier redaction, hash handling, RBAC, support bundle exports, and audit history.
- Customer acceptance evidence and signed release artifact bundle.

## Required Evidence

- Support bundle containing `api/wimax-service-flows.json` and `api/wimax-service-flows-history.json`.
- Production readiness report with `wimax_service_flows` not blocked.
- System status report exposing `wimax_service_flows`.
- Packet captures and decoded attribute matrix.
- HA replay and rollback report.
- Performance report and long-duration soak report.
