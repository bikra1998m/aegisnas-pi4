# Deployed Ubuntu service validation

**PASS: 21/21 probes. Production readiness: BLOCKED.** These probes test the existing installed lab deployment at commit `7004511cfbea5f30d53db9b6ac768e059d7cfaf1`, not the uncommitted candidate.

Actual execution included 8 active-service checks, 6 health endpoints, unauthorized admin API rejection, 4 authenticated read-only API endpoints, FreeRADIUS configuration validation and a real randomized nonexistent-user RADIUS Access-Reject. No user account or service configuration was changed. Credentials were consumed in memory and omitted from outputs.

All 8 service PIDs and start timestamps match before/after all admission tests. FreeRADIUS PID is 1430. No reboot, production restart, deployment, package installation/removal or database operation was performed. Previously owned PostgreSQL fixtures remained stopped. Root filesystem free space at final check was approximately 1.76 GB (96% used); test evidence was preserved.

The deployed readiness API still reports ready=false with 5 blockers: `radius_outbound_dac_client`, `radius_accounting_services`, `identity_source_failover`, `eap_machine_user_correlation`, `secret_providers`. Successful HTTP responses and an Access-Reject do not establish full NAS enforcement, HA, customer acceptance or production readiness.

Measured 10 successful loopback HTTP requests: minimum **0.476 ms**, median **1.835 ms**, maximum **3449.968 ms**. This small serial diagnostic sample is not a throughput, load, long-duration soak or Raspberry Pi benchmark. Those tests are NOT TESTED here.

Evidence: `.tmp/admission-guard-20261023/ubuntu-live.stdout`, `ubuntu-before.stdout`, `ubuntu3-after.stdout`, `verification.json`. No output contains the API bootstrap or SSH credential.
