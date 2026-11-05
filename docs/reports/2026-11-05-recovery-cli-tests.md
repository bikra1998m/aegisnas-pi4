# Recovery regression and live Ubuntu evidence — 2026-11-05

Current-slice results are separate from the earlier full-project checkpoint.
Windows and Ubuntu each executed the complete admin CLI unit suite: 36 passing
test/subtest events, zero failures and zero skips. `go vet ./cmd/aegis-admin` and
admin builds for Windows AMD64, Linux AMD64 and Linux ARM64 passed. ARM64 execution
on Raspberry Pi hardware is NOT TESTED. The new Python fixture syntax check passed.

| Actual isolated CLI fixture | Wall seconds measured inside fixture | PASS | SKIPPED |
| --- | ---: | ---: | ---: |
| windows_legacy | 13.889 | 36 | 1 |
| windows_sealed | 18.393 | 23 | 1 |
| ubuntu_legacy | 10.545 | 37 | 0 |
| ubuntu_sealed | 2.141 | 24 | 0 |

Every fixture has zero failures. Windows skips Linux permission certification;
these are explicit SKIPPED checks, not passes. Timings describe one small fixture
on each environment, not production capacity, latency percentiles or an RPO/RTO SLA.

The legacy fixture creates a new SQLite database, commits a WAL transaction while
keeping its client open, runs the real CLI, inspects the archive and restores it
only after closing fixture clients. It checks source preservation, exact manifest
coverage, config inclusion, archive no-overwrite, active-sidecar rejection, declined
restore, invalid manifest/database/path rejection, PostgreSQL guards, restored data
and integrity, retained safety copies and Linux modes. Unit tests additionally cover
duplicate/unsafe archives, malformed checksums, gzip corruption, file staging failure,
later replacement failure, failed compensation and aliased destinations.

Ubuntu was reached through existing verified-host SSH. Uploaded binaries, fixture
scripts and config template were SHA-256 checked remotely. The native test binary
and actual CLI ran under `/home/bikram/aegisnas-legacy-backup-20261105`, without
touching the NAS database, FreeRADIUS configuration or services. Before/after
read-only service captures match all eight deployed service identities. No reboot,
deployment, service restart or destructive database operation occurred.

Raw private evidence is under `.tmp/recovery-cli-20261105/`: `pre-fix-go.jsonl`,
`validation.json`, `pass2/`, `final-local/`, `windows-live/` and `ubuntu-live/`.
The first defect reproduction and first Windows URI failure remain FAIL records.
The final corrected runs above are separate PASS records. The evidence manifest
contains hashes of selected logs/results; private database, config, key and archive
contents are not committed. The earlier complete Windows suite, PostgreSQL 14/18,
117 RADIUS/accounting checks, browser suite and OS scan remain historical to source
`0578d45158454b707d0f41ab669741c47343ad84` until a new hosted run supplies current evidence.

Current-slice production PostgreSQL deployment, live telecom enforcement, multi-node
HA, power-loss recovery, full-image certification and production-scale performance
are NOT TESTED. No local fixture success closes those requirements.
