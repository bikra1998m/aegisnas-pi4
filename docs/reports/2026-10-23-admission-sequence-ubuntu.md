# Ubuntu admission regression

**PASS: 48 tests. FAIL: 0. SKIPPED: 0.** The exact final Python scripts matched Windows by SHA-256. Command: `python3 -m unittest discover -s scripts -p 'test_*.py' -v`; SSH command duration 0.903s. Raw final output: `.tmp/admission-guard-20261023/ubuntu3-python.stderr`. Runtime/platform inventory: `ubuntu3-environment.stdout`.

The private final fixture is `/home/bikram/aegisnas-admission-guard-20261023-attempt3-final`. It contains source/test evidence only. Tests use temporary private state, create real files, run actual locking/process-exit checks, exercise POSIX permission/link rejection and issue fsync/rename. No production state, database, package or service was modified. Power-loss/VM-reset recovery remains NOT TESTED.

The first run (`ubuntu-python.stderr`) has 25 PASS and 23 setup ERROR because the fixture policy inherited mode 0664 from umask 0002; production checks correctly rejected it. Explicit mode 0600 fixed the harness and CI. The second and final runs each passed all 48; only the final run includes the final path-normalization test extension. Failures and attempts remain preserved in separate files and remote directories.

Seven extracted release-workflow shell blocks passed actual Ubuntu `bash -n`; this is syntax validation, not execution of the hosted signing workflow. Final source equality and service-PID stability were verified.

Earlier Go/PG evidence is retained rather than rerun: October 23 changed packages radius/adminapi **705 PASS / 1 SKIPPED** combined; October 22 full Ubuntu Go **1,400 PASS / 2 SKIPPED**. Do not label the changed-package run as a full Ubuntu suite. Earlier database source is unchanged. See [PostgreSQL evidence](2026-10-23-admission-sequence-postgresql.md) and [fresh deployed probes](2026-10-23-admission-sequence-live-services.md).
