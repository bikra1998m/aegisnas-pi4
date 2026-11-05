# Ubuntu regression report — 2026-10-26

Final v5 source: **PASS 79, SKIPPED 0, FAIL 0**,
156.888s test time. This includes the existing security and
admission tests, new inventory tests, real SIGTERM handling, symlink/FIFO refusal,
and seven Bash build contracts plus recipe checks. The build contracts use
fake compiler/packager executables; they do not certify Snapcraft packaging.

Raw final logs: `ubuntu-regression-final.stdout`,
`ubuntu-regression-final.stderr`, `ubuntu-regression-final.json`, and
`ubuntu-v5-inputs.json`. Earlier 67- and 78-method passing runs are separate epochs.
The helper syntax check and ten YAML parses also passed. Hosted CI is NOT TESTED.

The initial real inventory was interrupted without a complete manifest. The
bounded follow-up saved BLOCKED partial evidence after reading 32 MiB and
completing zero file hashes. Full installed artifact inventory remains BLOCKED.
Actual Snapcraft/ubuntu-image builders are unavailable on this VM; no packages,
signed model/image or physical Pi execution were certified.

Deployed smoke batches: **16 PASS / 5 FAIL**, then **21 PASS**, then a further
**21 PASS after the compiler retry**. Systemd watchdog/startup failures and
automatic FreeRADIUS restarts remain an operational FAIL. Seven other service
identities remained unchanged, and post-recovery identities were stable at the
final check. The production-readiness API still reports five blockers.

Fresh full Go, database migration, PostgreSQL, browser and throughput/soak suites
are NOT TESTED in this continuation. Their prior evidence remains separate;
see [live service details](2026-10-26-appliance-live-services.md) and
[previous Ubuntu results](2026-10-26-recovery-ubuntu.md).
