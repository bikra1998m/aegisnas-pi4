# Existing deployment and service validation — 2026-10-26

The existing deployed lab services were probed separately from the new isolated
candidate. **Initial batch: 20 PASS, 1 FAIL.** The failed production-readiness
request exceeded a 20-second timeout. A targeted retry with the same deadline
returned HTTP 200 in 4.238 seconds. The cause of the transient
timeout is not established; the original failed result remains in the report.
Do not relabel this as a single 21/21 passing batch.

Eight services remained active with identical PIDs/start timestamps: gateway,
RADIUS daemon, portal, session, policy, admin API, FreeRADIUS and dnsmasq.
Health endpoints, authentication rejection and authenticated reads passed except
for the first readiness timeout. FreeRADIUS config validation passed and a real
random nonexistent identity received Access-Reject. No accounts were added.

The retry reports the deployment as **BLOCKED**, with five blockers:
`radius_outbound_dac_client`, `radius_accounting_services`,
`identity_source_failover`, `eap_machine_user_correlation`, `secret_providers`.
These readiness findings are distinct from dependency/OS vulnerability gates.

OS identity/dpkg hashes match the retained October 26 scan. The owned PostgreSQL
cluster and test/API processes stopped. Available root filesystem space after
tests was 30,092,881,920 bytes. No reboot, service restart, production activation,
database replacement, package installation or FreeRADIUS configuration edit was
performed. The earlier reboot authorization was not reused.

| Recovery CLI measurement | Windows | Ubuntu VM |
|---|---:|---:|
| Full fixture seconds | 6.778 | 8.362 |
| Snapshot/encryption command seconds | 1.428 | 0.945 |
| Authentication/extraction command seconds | 0.066 | 0.625 |

These are single populated test-database runs, not maximum-size, concurrent,
production-capacity or Pi certification. Raw CLI timings are in results.json.
The final environment-check file deliberately retains FAIL for the initial
probe batch; the successful targeted retry is a separate file.
