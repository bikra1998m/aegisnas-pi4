# Custom Ubuntu Core Image for AegisNAS Pi4

This directory contains assets to build a custom Ubuntu Core 24 image preloaded with all AegisNAS services as snaps. The resulting image can be flashed to a microSD card and booted on a Raspberry Pi 4.

## Prerequisites

- Ubuntu 24.04 LTS or newer (development machine)
- `snapcraft` installed and logged in (`snap install snapcraft --classic; snapcraft login`)
- `ubuntu-image` snap installed (`snap install ubuntu-image --classic`)
- Your developer ID registered in the Snap Store
- The AegisNAS snaps must be built and available (either locally or in the store)

## Workflow Overview

1. **Prepare model assertion** – Edit `model.json` with your developer ID and snap IDs.
2. **Sign the model** – Run `./sign-model.sh` to create `model.signed`.
3. **Build the image** – Run `./build-image.sh` to generate a flashable `.img` file.
4. **Flash to SD card** – Use `dd` or `balenaEtcher` to write the image to a microSD card.
5. **First boot** – Insert SD card into Raspberry Pi 4 and power on.

## Development vs Production Signing

### Development Workflow (Unsigned / Dangerous Model)

During development, you can build an image with an unsigned model (using `--dangerous` flag with ubuntu-image). This is useful for local testing without store involvement.

```bash
ubuntu-image snap model.json --dangerous