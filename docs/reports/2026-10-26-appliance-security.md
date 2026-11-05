# Dependency, OS and appliance security — 2026-10-26

**Final release-security decision: BLOCKED. No security policy waiver.**

## Current continuation evidence

The new collector inventories files rather than interpreting nested package
metadata. Snap filenames are extension-based classifications, not proof of
SquashFS validity, Store identity, active revision, signature or safe content.
Firmware/boot hashes do not identify device-loaded firmware or EEPROM contents.
Synthetic unit fixtures are not real snap packages or firmware certification.

Real full collection failed to complete. The final 10-second bounded attempt
read 33,554,432 bytes, completed zero file hashes and retained BLOCKED scopes
for snap store, firmware and boot. No complete manifest verification is claimed.
Unit and CLI fixtures verify unchanged-content comparison, tamper/add/remove
rejection, limits, Linux aliases, FIFO/link refusal and real cancellation.

Full image acceptance still needs nested snap inventories/scans, firmware
vendor/version/advisory mapping, artifact-to-image binding, assertion/provenance
verification, real signed model/Store identities and Pi boot/EEPROM evidence.
The source Core model retains placeholders. Classic-confinement RADIUS is an
additional architecture/integration blocker, documented with primary references
in the [image guide](../../image/README.md).

## Retained dependency and OS evidence (not newly scanned here)

All six Go/npm dependency input files are unchanged. The preserved dependency
inventory records 65 Go and 184 npm components; npm audit had zero findings and
module verification passed in that earlier evidence epoch. The prior corrected
Go scans on both shipped targets retained GO-2026-5932 in
`golang.org/x/crypto v0.58.0`, with no fixed version in the retained advisory.
The finding was module-level; advisory OpenPGP packages were absent from the
shipped command import graphs. This does not prove symbol reachability or
exploitability, and the conservative gate still blocks it.

The retained Trivy 0.76.0 installed-OS scan recorded 1,733 components, 73,985
finding occurrences and 7,805 unique IDs. Blocking occurrences were 9,380
(400 Critical, 8,980 High), representing 964 blocking IDs across 18 installed
packages. These are installed-package scanner results, not a claim that each
vulnerability is reachable in shipped NAS runtime code. This desktop Ubuntu
VM is not the exact Raspberry Pi image. Snap contents and firmware remain outside
that dpkg-derived coverage.

Fresh read-only hashes of `/etc/os-release`, `/etc/lsb-release` and
`/var/lib/dpkg/status` match the retained scan inputs exactly. This revalidates
those input identities, not all filesystem content or a new advisory database
scan. The retained advisory update timestamp was
`2026-10-26T07:15:18.945937093Z`.

See the preserved [previous security report](2026-10-26-recovery-security.md)
and its evidence manifests for exact scanner commands and failures. No new
clean committed candidate, trusted attestation workflow, actual signed-candidate
verification, full-image signature or production activation occurred here.
Actual signing availability was not newly probed; unprovisioned model IDs and
the failed security/operational gates already prevent certification.
