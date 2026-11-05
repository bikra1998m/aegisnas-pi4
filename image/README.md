# Ubuntu Core image reference assets

Status: **BLOCKED for production image creation and certification**. The model
and helper scripts are reference assets. They do not establish that a bootable,
signed, secure AegisNAS Raspberry Pi image has been built or tested.

The checked-in `model.json` contains placeholder brand/authority and essential
snap IDs, and empty AegisNAS snap IDs. These require real registered identities,
published snap assertions, an appropriately registered signing key and a
current complete model assertion. A signed-grade model requires asserted
snaps; editing IDs or locally hashing a file is not signature verification.
See Canonical's [model assertion reference](https://documentation.ubuntu.com/core/reference/assertions/model/)
and [custom snap image guidance](https://documentation.ubuntu.com/core/how-to-guides/image-creation/add-custom-snaps/).

The current RADIUS recipe uses classic confinement and expects host FreeRADIUS.
Canonical documents that [classic snaps cannot run on Ubuntu Core](https://snapcraft.io/docs./reference/administration/reviewing-classic-confinement-snaps/).
Do not treat changing the confinement string as a fix: implement the required
runtime packaging, interfaces, configuration/data ownership and service control,
then run real confinement and packet tests. The other service recipes also need
shared storage/interface and runtime dependency validation.

Before an image can be considered for release:

1. Resolve packaging and confinement gaps; build every actual snap in an isolated
   supported build environment and test it.
2. Provision the real Store identities/model assertions and review signing
   permissions. `sign-model.sh` alone is not a trusted release-security workflow.
3. Attach exact snap, kernel, gadget, base, firmware and boot inventories; scan
   nested packages and map firmware advisories to deployed hardware versions.
4. Bind those artifacts and a passing security policy to the exact signed image,
   with verified provenance and downgrade protection.
5. Test boot, enrollment, updates, failed updates and coordinated recovery on
   Raspberry Pi hardware. An AMD64 Ubuntu VM cannot provide this certification.

`build-image.sh` invokes `ubuntu-image`; it has no integrated NAS-0116 admission
or production activation gate. Do not use its success message as release
acceptance or assume a specific image filename without examining actual output.
Neither helper is invoked by the read-only inventory tool.

See [snap packaging](../snaps/README.md),
[artifact inventory](../docs/appliance-artifact-inventory.md) and
[release security](../docs/supply-chain-release-security.md).
