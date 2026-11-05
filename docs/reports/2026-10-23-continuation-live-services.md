# Live deployment and service validation — October 23

**Existing Ubuntu deployment: 21/21 probes PASS. Readiness: BLOCKED (5 blockers).** These probes test the installed deployment, not the uncommitted candidate.

Eight systemd services were active; six real HTTP health endpoints responded; unauthenticated roles correctly returned 401; authenticated roles, database, readiness and status requests succeeded; `freeradius -Cx` passed; a random nonexistent identity received Access-Reject. No account was created for the negative PAP check. Credentials were read only inside the privileged probe and were not printed or copied into reports.

The readiness response reports {"status": "blocked", "ready": false, "score": 0, "blocking_count": 5, "warning_count": 4, "degraded_count": 17, "passing_count": 68}. Known open readiness checks remain outbound DAC clients, accounting services, identity failover, EAP machine/user correlation and secret providers. Successful HTTP responses do not override those blockers.

Measured timings are preserved per request in the raw probe. These are individual localhost service response times under the recorded VM conditions; NOT a throughput, concurrency, NAS forwarding or production SLO benchmark. Long-duration accounting/session and representative device/pool load remain NOT TESTED.

The new SQL fixture is separate: 22 checks PASS, real TLS/SCRAM SQL-backed RADIUS packets, negative certificates and fixture-only outage/reconnect. Production FreeRADIUS config, NAS deployment and databases were preserved; this continuation issued no production service interruption, reboot or production migration. No candidate was activated. A post-test read-only check found all eight services active with start times predating the initial VM inventory, all three private fixture postmasters stopped, and 1,762,545,664 bytes available on the root filesystem (96% used). Existing deployment probes remain evidence for only the checks actually executed, not all 90 engineering-complete roadmap items.
