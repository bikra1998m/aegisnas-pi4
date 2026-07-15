# NAS-0016 Release Certification Checklist

NAS-0016 software engineering is complete when the fallback policy, portal
enforcement, durable audit history, APIs, UI, readiness checks, tests, and
documentation are merged.

This checklist tracks evidence that requires production Linux packages, packet
captures, upstream AAA systems, vendor devices, HA labs, security review, or
customer environments. These items do not keep NAS-0016 open for software
development.

## Software Closure

| Item | Status |
|---|---|
| Configuration schema and validation | Complete |
| Effective fallback policy evaluator | Complete |
| Portal local/LDAP fallback enforcement | Complete |
| Hashed fallback audit event persistence | Complete |
| Admin API and system status integration | Complete |
| Production readiness integration | Complete |
| Admin UI controls and dashboard summary | Complete |
| Unit, DB, API, OpenAPI, RBAC, readiness, support bundle, and CI target coverage | Complete |
| Operator and API documentation | Complete |

## External Certification

| Evidence | Required Result |
|---|---|
| Ubuntu FreeRADIUS package validation | Broker outage and recovery behavior is reproducible on supported Ubuntu releases |
| Upstream AAA outage drill | Portal fallback grants only allowlisted identities during a controlled upstream auth outage |
| Enforce negative drill | Non-allowlisted valid local/LDAP users are denied during outage in enforce mode |
| Monitor-mode migration drill | Monitor mode records would-deny events without changing legacy behavior |
| Packet capture validation | Normal broker auth and accounting packets remain unchanged when fallback is idle |
| Vendor interoperability | Claimed AP/controller captive portal workflows tolerate upstream outage and recovery for exact firmware scope |
| HA validation | Active/standby nodes share fallback audit state and evaluate the same policy after failover |
| Upgrade and rollback | Existing `portal.local_fallback` deployments upgrade in monitor mode and rollback without data loss |
| Performance benchmark | Policy evaluation and audit writes meet target login throughput on low-spec and enterprise profiles |
| Long-duration soak | Repeated outage/recovery cycles keep audit retention, readiness, and dashboard state stable |
| Security review | Logs, APIs, support bundles, and exports contain hashed identities and no passwords or RADIUS secrets |
| Customer acceptance | Target deployment signs off fallback identity scope, outage window, and recovery operating procedure |

## Sign-Off Artifacts

- `/api/v1/system/fallback-policy` output
- `/api/v1/system/production-readiness` output
- redacted portal outage drill transcript
- monitor-mode and enforce-mode decision exports
- packet captures with secrets redacted
- HA failover transcript
- upgrade and rollback transcript
- performance and soak reports
- security-review notes
- customer approval record
