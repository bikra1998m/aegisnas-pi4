# NAS-0015 Release Certification Checklist

NAS-0015 software engineering is complete when the transport downgrade policy,
generation enforcement, APIs, UI, readiness checks, tests, and documentation are
merged.

This checklist tracks evidence that requires external systems, production Linux
packages, packet captures, vendor devices, HA labs, or customer environments.
These items do not keep NAS-0015 open for software development.

## Software Closure

| Item | Status |
|---|---|
| Configuration schema and validation | Complete |
| Effective transport policy evaluator | Complete |
| Mixed UDP/RadSec route detection | Complete |
| Enforce-mode FreeRADIUS generation blocker | Complete |
| Admin API and system status integration | Complete |
| Production readiness integration | Complete |
| Admin UI controls and dashboard summary | Complete |
| Unit, integration, API, OpenAPI, RBAC, generator, and CI target coverage | Complete |
| Operator and API documentation | Complete |

## External Certification

| Evidence | Required Result |
|---|---|
| Ubuntu FreeRADIUS package validation | Generated `proxy.conf` keeps `default_fallback = no` and validates with `freeradius -XC` for supported Ubuntu releases |
| Packet capture validation | RadSec routes do not send traffic to UDP peers when enforce mode blocks mixed pools |
| Mixed-pool negative drill | A route with RadSec and UDP peers fails preview/apply/generation in enforce mode |
| Explicit exception drill | A documented UDP or mixed route exception is visible in `/api/v1/system/transport-policy` and accepted by the change board |
| Vendor interoperability | Claimed AP/controller/proxy products follow expected failover behavior for the exact firmware scope |
| HA validation | Active/standby nodes evaluate the same transport policy and fail over without changing route transport intent |
| Upgrade and rollback | Existing UDP-only deployments upgrade in monitor mode, then can move to enforce mode; rollback restores prior route behavior |
| Performance benchmark | Policy evaluation adds no measurable latency to proxy generation or health/status calls at target route scale |
| Long-duration soak | Route transport reports, upstream history, and readiness remain stable during transport outages |
| Security review | Logs, APIs, support bundles, and UI do not expose shared secrets while reporting transport policy evidence |
| Customer acceptance | Target deployment signs off required transports, mixed-pool exceptions, and downgrade policy language |

## Sign-Off Artifacts

- generated FreeRADIUS archive
- `freeradius -XC` output
- packet captures with secrets redacted
- `/api/v1/system/transport-policy` output
- `/api/v1/system/production-readiness` output
- mixed-pool negative test transcript
- explicit exception approval record
- HA failover transcript
- upgrade and rollback transcript
- security-review notes
