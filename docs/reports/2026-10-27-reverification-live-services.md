# Live Ubuntu deployment validation — 2026-10-27

The existing deployed software was probed; the new working tree was not deployed.
Initial smoke: **19 PASS / 2 FAIL out of 21**. Both failures were authenticated
GET timeouts (production readiness and system status) at the 20-second deadline.
The separate same-deadline retry passed both routes in
2.837s and 4.729s.

All eight monitored service identities (PID/start time/state) matched before,
after and at the final validation snapshot. No reboot or service restart was
issued. Health routes, authentication rejection, authenticated roles/database,
FreeRADIUS configuration validation and a real nonexistent-user PAP Access-Reject
passed in the first batch. This does not certify every roadmap feature in production.

Readiness remains **BLOCKED**: five blocking, four warning, seventeen degraded
and sixty-eight passing checks. The blockers concern outbound DAC, RADIUS
accounting services, identity-source failover, EAP machine/user correlation and
secret providers. The reason for the transient control-plane timeouts is not
established. The previous day's watchdog failures remain in their original reports;
they are not mislabeled as new restarts or discarded because current identities match.

Only small isolated Python fixtures were uploaded/executed in fresh private
directories under `/home/bikram/aegisnas-reverification-20261027-*`. Positive
signature checks in those fixtures were mocks; no fixture is a trusted release.
No existing deployment/configuration/FreeRADIUS data was replaced. Production
backup/restore, PostgreSQL migrations, large file inventories and heavy compiles
were not invoked. Current OS identity/dpkg status hashes match the retained
scan inputs; that is not a new OS vulnerability scan.

Evidence: `vm-before.stdout`, `vm-after.stdout`, `vm-final.stdout`,
`deployed-probes.stdout`, `failed-route-retry.stdout`, `ubuntu-full.stderr`,
`ubuntu-final.stderr` and `ubuntu-complete.stderr`. Initial failed tests and
timeouts are retained separately from retries.
