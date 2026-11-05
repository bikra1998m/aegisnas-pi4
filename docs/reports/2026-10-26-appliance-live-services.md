# Live Ubuntu deployment validation — 2026-10-26

**Operational acceptance: FAIL. Latest smoke retry: PASS 21/21.** These are
distinct conclusions. The existing deployment was tested; the uncommitted
candidate was not installed or promoted.

The first 21-check deployed batch passed 16 and timed out on health ports 8082
and 8083, authenticated database, production readiness and system status. After
owned heavy work stopped, the same probe passed all 21: eight service states,
six health routes, unauthenticated rejection, authenticated API reads,
FreeRADIUS configuration validation and real nonexistent-user PAP Access-Reject.

The read-only inventory and concurrent host work coincided with severe slowdown.
The exact root cause is not established. Journal evidence also shows a watchdog
timeout before collection, at 12:22:10 UTC. During this run, additional watchdog
timeouts occurred at 13:13:37 and 13:14:04; systemd killed FreeRADIUS, retried a
startup that timed out, and started it successfully at 13:19:55 UTC. The process
changed from PID 7053 to 8423. Seven other monitored service identities remained
unchanged. Do not report uninterrupted service continuity or dismiss the failures
because later probes passed. No watchdog timeout or security policy was relaxed.

The collector was lowered to CPU nice 19 and idle I/O priority, the owned `du`
probe was stopped, and then only the verified collector PID was interrupted.
A first SSH stop attempt failed on banner timeout; a later connection succeeded.
The old collector lacked graceful partial reporting, so its interrupted attempt
has no complete inventory manifest. The revised bounded collector retained a
blocked report after its 10-second budget. No inventory process remained at the
recorded cleanup check. Initial build descendants were also explicitly cleaned up.

The API still reports `ready:false`: five blocking, four warning, seventeen
degraded and sixty-eight passing readiness checks. The five blockers are
outbound DAC, RADIUS accounting services, identity-source failover,
EAP machine/user correlation and secret providers. Current smoke availability
does not close these functional or operational requirements.

The agent did not issue a reboot, service stop/start/restart, production
deployment, package upgrade, database restore or FreeRADIUS configuration write.
Systemd's automatic restarts are recorded as actual service interruptions.
Root free space at the post-test check was approximately 30.08 GB. Do not repeat
unbounded full inventories alongside live traffic on this constrained lab host;
qualify complete image inventories on an isolated immutable build/snapshot host.

Raw evidence: `vm-before.stdout`, `vm-after.stdout`, `vm-final.stdout`,
`deployed-probes-final.stdout`, `deployed-probes-retry.stdout`,
`service-lifecycle.stdout`, `vm-priority.stdout`, `vm-stop-inventory.stdout`,
`live-inventory-bounded.json`, and `owned-process-check.stdout` in
`.tmp/appliance-inventory-20261026/`. Compiler retry health probes are separate
availability samples, not an authentication/load certification. The guarded
compiler retry also timed out; 27 health samples passed and one timed out.
After its owned process tree was stopped, a further complete smoke batch passed
21/21. All eight service identities were stable relative to the recovered
post-watchdog state, and no owned inventory process remained. See
`deployed-probes-postbuild.stdout` and `vm-postbuild.stdout`.
