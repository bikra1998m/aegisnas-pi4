# Snap Packaging for AegisNAS Services

This directory contains snapcraft configurations for all AegisNAS microservices, designed for deployment on Ubuntu Core 24.

## Prerequisites

- Ubuntu Core 24 or Ubuntu 24.04 LTS with snapd.
- `snapcraft` installed (`sudo snap install snapcraft --classic`).
- FreeRADIUS installed on the host for `aegis-radius` to manage (or use the `freeradius` snap).

## Building Snaps

Run the build script:

```bash
cd snaps
./build-all.sh