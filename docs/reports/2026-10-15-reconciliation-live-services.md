# Live deployment and service validation

**PASS for the tested lab services and isolated current API processes. Release readiness remains BLOCKED.**

The current read-only SSH probe at `2026-10-15T11:39:54.643046+00:00` confirmed eight active services (`aegis-gateway`, `aegis-radius`, `aegis-portal`, `aegis-session`, `aegis-policy`, `aegis-admin-api`, FreeRADIUS, dnsmasq) and six HTTP health endpoints on ports 8080, 8081, 8082, 8083, 8085 and 8087: **14 checks PASS**. The deployed commit remains `7004511cfbea5f30d53db9b6ac768e059d7cfaf1`. Its OS package and release-file hashes match the earlier vulnerability evidence. The initial and final probes each passed all 14 checks, and the boot ID remained unchanged. Final disk was 91% used with 3.5 GB available; validation data and caches were preserved.

The previous **21 passing recovery checks** are retained separately: service/health checks, authenticated and unauthenticated API behavior, FreeRADIUS `-Cx`, and a real negative PAP request receiving Access-Reject. The expected radclient nonzero exit on rejection was not misreported as authentication success. Those protocol/config checks were not needlessly repeated. Current FreeRADIUS service activity is newly checked; positive credential authentication, broad EAP/RadSec interoperability and physical-device enforcement are **NOT TESTED** here.

## Current code, isolated process tests

Newly built admin/API binaries passed **15 checks on Windows and 15 on Ubuntu**, with a fresh SQLite database, temporary config and random ephemeral token. Checks cover config validation, migration, seed, health, auth rejection, accurate unsigned release state, database status, DOCSIS/upgrade preview, roles, OpenAPI, built frontend serving and actual support-bundle ZIP contents. Existing UI build artifacts were reused because UI source and dependencies were unchanged. No uncommitted binary replaced the deployed NAS service.

| 100 sequential loopback requests | Windows | Ubuntu VM |
|---|---:|---:|
| Median ms | 15.063 | 0.625 |
| p95 ms | 16.369 | 3.499 |
| Maximum ms | 25.852 | 42.827 |

This measures `/api/v1/system/release-security` in the missing-admission state at concurrency one. Concurrent host/VM work makes these descriptive samples, not a controlled regression comparison. Earlier fuzz/microbenchmark results remain in the original test report; they were not rerun because those algorithms were unchanged. NAS forwarding, RADIUS load, long-duration soak and target-hardware performance remain **NOT TESTED**.

Raw evidence: `.tmp/reconcile-20261015/vm-readonly.json`, `live-api/result.json`, `vm-api-result.json`, and the associated driver/build logs. Owned API processes terminated through the harness; private PostgreSQL instances stopped after their tests. No reboot, production restart, package upgrade, database replacement, FreeRADIUS edit or deployment occurred.

See [security findings](2026-10-15-reconciliation-security.md), [PostgreSQL evidence](2026-10-15-reconciliation-postgresql.md), and the [readiness assessment](2026-10-15-reconciliation-readiness.md).
