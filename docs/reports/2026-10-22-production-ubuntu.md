# Ubuntu regression report

| Execution | Status | PASS | FAIL | SKIPPED |
|---|---|---:|---:|---:|
| Ubuntu full Go 1.26.10, cross-built then run natively | PASS | 1400 | 0 | 2 |
| Ubuntu PostgreSQL 14.24, Go 1.26.10 | PASS | 152 | 0 | 0 |
| Ubuntu full Go 1.26.9 | PASS | 1400 | 0 | 2 |
| Ubuntu PostgreSQL 14.24, Go 1.26.9 | PASS | 152 | 0 | 0 |
| Ubuntu initial assertion failures | FAIL | 1391 | 3 | 2 |
| Ubuntu disk-full attempt | FAIL | 333 | 0 | 0 |
| Ubuntu PostgreSQL timeout attempt | FAIL | 145 | 2 | 0 |

The Go 1.26.9 serial run executed all packages, the real PostgreSQL matrix, Python security tests, Linux AMD64 and ARM64 builds, vet and two real API matrices on the Ubuntu VM. Its final source hash check passed. It predates the Go 1.26.10 security patch.

The current patched test executables are cross-built on Windows using Go 1.26.10, transferred by SHA-256 and executed natively on Ubuntu from their source package directories. A separately cross-built Go 1.26.10 test2json program adapts output. The first launcher assumed an absent Go 1.26.9 adapter path and exited 127 before executing assertions; those failures are retained in patched-vm3 and vm-decoder-attempt.json. The corrected launcher reuses successful cross-builds after checking source stability. This is native Ubuntu execution, not native Ubuntu compilation with Go 1.26.10. ARM64 is build-tested only; Raspberry Pi execution is NOT TESTED.

Earlier failures were genuine and retained: accounting-spool NOT NULL defects (fixed), PostgreSQL UTC/format/int4/fixture assertions (fixed), migration/schema cleanup timeouts, and link failures when the 39-GB VM root filesystem filled. Overlapping obsolete runs were cancelled, not promoted to PASS.

Capacity recovery removed only regenerable compiler cache entries touched on October 22 (8,138 files, 1,203,095,373 bytes) and two identified orphan compiler scratch directories. The attempted cache archive was cancelled and is INCOMPLETE; it is not a valid preservation archive. Source, test databases, deployed data and test logs were preserved. Cleanup receipts and the incomplete archive remain. A later pause request found no validation runner because the serial run had already finished; its completed results were fetched and checked.

The final capacity check reclaimed another 6,663 regenerated cache files (775,592,996 bytes), increasing root free space from 1,177,624,576 to 1,977,094,144 bytes. Both cleanup receipts remain; neither cleanup removed test data or logs. The VM still has limited disk headroom and is not capacity-certified.

Raw native evidence: `.tmp/production-20261022/patched-vm4/`; previous serial evidence `vm-serial-*`; failure/capacity receipts remain in the same parent. No deployed services were restarted or replaced during this continuation.
