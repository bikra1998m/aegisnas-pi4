# Current implementation audit — 2026-10-26

Audit baseline: `2026-10-26T12:45:22.013841+00:00`, HEAD `7004511cfbea5f30d53db9b6ac768e059d7cfaf1`,
410 pre-existing Git status entries, 1369 repository files,
114 existing reports. This run changes 22 implementation/test/workflow/guide files.
The [change ledger](2026-10-26-appliance-changes.csv) records each path's before/after SHA-256;
it isolates this continuation from the much larger inherited working tree.

## Implemented and tested

`inventory_appliance.py` streams bounded SHA-256 inventories of snap-store,
firmware and boot files, supports rooted Linux/merged-usr links, rejects scope
escapes and special files, checks file identities/mutation and directory membership,
and compares against an independently approved manifest digest. Verification
rejects symlink/FIFO manifests before opening them. Missing paths, permission
failures, limits and cancellation cannot become an inventory PASS. Output is
exclusive and outside the scanned directories. A successful inventory always
retains a BLOCKED release gate: it is neither a vulnerability scan nor a signature.

Bounds: 100,000 entries, 8 GiB per file, 32 GiB bytes read, 64 MiB manifest,
300-second default collection budget (1..3600 configurable). SIGINT/SIGTERM and
time expiry retain blocked partial evidence after the current read returns.
Kernel-stalled I/O is not given a hard interrupt deadline. The tool observes a
live tree; it cannot establish atomicity against a privileged concurrent writer.

Eight snap recipes now use the shared `build-snap-service.sh` helper from
`CRAFT_PART_SRC`, with exact `go.mod` compiler selection, checked GOVERSION,
CGO disabled, read-only modules and explicit AMD64/ARM64 target validation.
The previous recipes requested a Go 1.22 bootstrap and used `cd ../../` after
the default build. The old bootstrap could auto-select another toolchain;
there is no evidence that a shipped binary actually used Go 1.22.

`snaps/build-all.sh` resolves absolute project paths, preserves build workspaces,
requires a new output directory, stops on failure/missing artifacts, and writes
checksums only after all eight outputs exist. It does not upload, install or sign.
Main CI now runs all Python security/inventory/build-contract tests; release CI
already discovers them. Hosted workflow execution is NOT TESTED.

## Limits and preserved behavior

No Go, database schema, admin API/UI or running deployment files changed in this
continuation. 908 Go/module input hashes match the preceding recovery
verification epoch. No dependency versions were changed. Existing runtime
evidence remains historical and source-specific, rather than a new full run.

Full Snapcraft builds, confinement and Pi image qualification remain unverified.
The RADIUS classic-confinement recipe cannot establish an Ubuntu Core deployment;
actual runtime/interface packaging work remains. Placeholder Store IDs remain
unfilled; no identity, signature or production certification was fabricated.
File inventory is not nested-package coverage or firmware advisory mapping.
Coordinated admission/activation/DB/config recovery remains unfinished.

The new guide, image/snap READMEs, development guide, checklist, roadmap and
NAS-0116 backlog row explain these boundaries. Other feature classifications
and unrelated local changes are preserved. See [tests](2026-10-26-appliance-tests.md) for
failures and [security](2026-10-26-appliance-security.md) for the final gate.
