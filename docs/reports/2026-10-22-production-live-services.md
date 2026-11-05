# Live deployment and service validation

Latest existing-deployment probe: **21/21 PASS**. Installed deployment stamp: `7004511cfbea5f30d53db9b6ac768e059d7cfaf1`. The API still reports readiness **blocked**, with 5 blockers. Successful HTTP probes are not production-readiness approval.

Checks cover eight active services, six health routes, unauthenticated 401, authenticated roles/database/readiness/status, FreeRADIUS configuration validation, and a random nonexistent PAP identity returning Access-Reject. The radclient command may exit 1 for the expected reject; the response packet determines that negative test's PASS.

The preceding loaded attempt passed 18/21: readiness/status requests timed out and RADIUS did not respond within the probe budget. The quiet retry passed 21/21. Both attempts remain; workload contention is a plausible explanation, not a proven root cause. No restart or reboot was used for the retry.

Readiness blockers observed on the installed deployment: outbound CoA/disconnect client, multi-service accounting correlation, identity-source failover, machine/user correlation and secret providers. Those configuration/status reports alone do not establish all underlying functionality.

| Backend execution | Status | Checks | Loopback median / p95 / max ms |
|---|---|---:|---|
| Windows SQLite, Go 1.26.10 | PASS | 220 | 15.096 / 16.205 / 24.601 |
| Ubuntu SQLite, Go 1.26.10 | PASS | 220 | 0.520 / 0.817 / 3.492 |
| Ubuntu PostgreSQL, Go 1.26.10 | PASS | 220 | 0.887 / 1.488 / 38.018 |
| Ubuntu SQLite, Go 1.26.9 | PASS | 220 | 0.561 / 0.875 / 41.944 |
| Ubuntu PostgreSQL, Go 1.26.9 | PASS | 220 | 0.971 / 1.396 / 38.440 |

Isolated API matrices execute actual backend binaries and fetch the built frontend, migration/seed, authentication failures, API/support-bundle/release-security behavior and parameter-free system GET routes. Each matrix excludes 50 parameterized/download/export routes; write/device/controller paths are not automatically certified. Disabled controller preview returns the expected 400 and unsupported PostgreSQL file replication the expected 409.

Performance is 100 sequential loopback requests, concurrency one, to the missing-admission release-security endpoint. It is not forwarding throughput, authentication capacity, concurrent load or an SLA. No production latency claim is inferred from isolated measurements.

The deployed FreeRADIUS configuration and data were preserved. Existing NAS deployment was not replaced by the candidate. All 135 feature packages are mapped in the [milestone ledger](2026-10-22-production-milestones.csv); shared regression does not make every feature's production acceptance PASS.
