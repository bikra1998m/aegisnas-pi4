# Snap packaging for AegisNAS services

Status: **lab packaging; production certification incomplete**. The eight
recipes compile service payloads using the exact patched Go version in
`go.mod`, `CGO_ENABLED=0`, and the Snapcraft build target (`amd64` or `arm64`).
The shared helper runs from the repository source directory instead of relying
on the caller's working directory. The Go build snap supplies the bootstrap
compiler; `GOTOOLCHAIN` selects the exact repository version and may require
access to the Go toolchain/module download services.

On an isolated Ubuntu build host with Snapcraft and its supported build
environment installed, choose a new output directory whose parent exists:

```bash
bash snaps/build-all.sh /protected/builds/aegis-lab-snaps-001
```

The wrapper builds all eight projects, requires each output, and writes
`SHA256SUMS` only after all builds succeed. It refuses an existing output
directory and preserves prior workspaces and partial failures. It does not
clean workspaces, install packages, upload snaps or change appliance services.
If a clean build is required, use a fresh isolated checkout/build environment.

The recipes use the documented [override-build source directory](https://ubuntu.com/docs/snapcraft/latest/reference/snapcraft-yaml/)
and [pack command](https://ubuntu.com/docs/snapcraft/9/reference/commands/pack/).
Tests with fake compiler/packager processes verify paths, error propagation,
artifact checks and preservation. Those tests do not constitute a real
Snapcraft package build, Store review or confinement test.

Production blockers remain:

- `aegis-radius` uses classic confinement and manages host FreeRADIUS. Classic
  snaps are [unsupported on Ubuntu Core](https://snapcraft.io/docs./reference/administration/reviewing-classic-confinement-snaps/).
  A supported RADIUS packaging, interface and service integration design must be
  implemented and tested before this appliance can use Core.
- Shared database/config paths, system-files/content interfaces, runtime tools,
  daemon startup and privilege boundaries need actual confinement validation.
- Real Snap Store identities, assertions, signed image composition, nested
  dependency scans, firmware review and admission/activation binding remain open.
- The existing Go/OS security blockers are not waived by successful compilation.

See [image prerequisites](../image/README.md),
[artifact inventory](../docs/appliance-artifact-inventory.md) and the
[NAS-0116 checklist](../docs/nas-0116-release-certification-checklist.md).
