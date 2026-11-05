# Ubuntu native regression evidence

Implementation and the main regression suites were executed on **October 23, 2026**. This report was reconciled on **October 26** without changing tested runtime sources. October 26 evidence is labeled separately; earlier attempts remain preserved. The filename retains the implementation start date.

The available lab is Ubuntu 22.04 on AMD64 with FreeRADIUS 3.0.26 and extracted PostgreSQL 14 binaries. Current Go 1.26.10 Linux binaries were built on Windows and actually executed in the guest. All current test/API binaries were uploaded before the final runner started; their hashes are in the source-state report.

| Native package | PASS | FAIL | SKIPPED |
|---|---:|---:|---:|
| db | 155 | 0 | 1 |
| radius | 378 | 0 | 2 |
| adminapi | 328 | 0 | 0 |

The three package runs cover shared DB logic, RADIUS generation/accounting and admin integration. They are not a fresh entire Ubuntu `go test ./...` run. The earlier complete Ubuntu suite (1,400 passes/two skips on October 22) remains historical. Limited guest disk space made a new full toolchain/cache build unsuitable; only current cross-built binaries and isolated fixtures were transferred.

Actual generated accounting/post-auth packet fixture: **PASS**, 117 checks. Actual PostgreSQL 14 functional matrix: **PASS**, 156 passes, fsync off only in its disposable schema-churn cluster. SQLite and PostgreSQL API smoke: **PASS**, 220 and 220 checks. No production services/configuration/database were replaced. Hosted CI, ARM64 execution, vendor hardware, HA and long soak remain NOT TESTED.

Raw evidence: `.tmp/sql-accounting-20261023/native-verified/`, `attempt13-verified/`, `native-verified-upload.json`. The old VM checkout supplies unchanged runtime fixture files; executable code comes from the new binaries. Existing deployment probes are separately reported and do not certify this code as deployed.

October 26 separately executed checks: default-durability PostgreSQL 14 matrix **PASS** (156 passes, zero failures and zero skips), packet fixture **PASS** (117 passing checks) and 21 deployed probes. The unchanged source and previously verified binaries were reused; the October 23 three-package suite was not rerun or relabeled as a new full suite.
