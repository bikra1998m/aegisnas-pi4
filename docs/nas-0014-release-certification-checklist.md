# NAS-0014 Release Certification Checklist

NAS-0014 software engineering is complete for RadSec X.509 mTLS, outbound
TLS-PSK, credential rotation, redacted status APIs, readiness checks, UI, tests,
and documentation.

This checklist tracks release evidence that requires external systems,
production Linux packages, vendor devices, HA labs, or third-party review. These
items do not keep NAS-0014 open for software development.

## Software Closure

| Item | Status |
|---|---|
| Configuration schema and validation | Complete |
| Outbound TLS-PSK FreeRADIUS generation | Complete |
| Active-window PSK rotation selection | Complete |
| Secret-reference resolution and redaction | Complete |
| RadSec credential status API | Complete |
| System status and production readiness integration | Complete |
| Admin UI configuration and dashboard state | Complete |
| Unit, integration, API, OpenAPI, RBAC, generator, and CI target coverage | Complete |
| Operator and API documentation | Complete |

## External Certification

| Evidence | Required Result |
|---|---|
| Ubuntu FreeRADIUS package validation | `freeradius -XC` accepts generated mTLS and TLS-PSK proxy configuration on each supported Ubuntu release |
| FreeRADIUS TLS-PSK handshake proof | Packet capture and FreeRADIUS logs show successful outbound TLS-PSK connection with current and next identities |
| Rotation drill | Stage next PSK, confirm current identity before `next_not_before`, confirm next identity during the active window, and confirm fail-closed behavior after expired staged windows |
| Vendor or roaming-partner interoperability | Each claimed upstream product, firmware, or federation profile completes Access, Accounting, Status-Server where supported, and failure-path tests |
| HA validation | Active/standby nodes share configuration state, preserve secret-reference expectations, and fail over without exposing secret material |
| Upgrade and rollback | Old version to NAS-0014 upgrade preserves mTLS peers; rollback leaves unsupported TLS-PSK peers disabled or clearly blocked |
| Performance benchmark | TLS connection pools meet stated authentication and accounting throughput targets without queue saturation |
| Long-duration soak | Sustained RadSec traffic, credential warnings, and history collection remain stable for the release soak window |
| Security review | Secret references, generated configs, logs, support bundles, API responses, and UI views are checked for credential disclosure |
| Customer acceptance | Target deployment signs off exact partner identities, PSK length/format, rotation windows, and downgrade policy |

## Sign-Off Artifacts

- generated FreeRADIUS archive
- `freeradius -XC` output
- packet captures with secrets redacted
- `/api/v1/system/radsec-credentials` output
- `/api/v1/system/production-readiness` output
- upgrade and rollback transcript
- HA failover transcript
- security-review notes
