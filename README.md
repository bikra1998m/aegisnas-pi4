# AegisNAS Pi4

[![CI](https://github.com/bikra1998m/aegisnas-pi4/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/bikra1998m/aegisnas-pi4/actions/workflows/ci.yml)

AI-assisted NAS / AAA gateway for Raspberry Pi 4 class hardware and Ubuntu Core 24.

The repository builds as a production-minded MVP: Go services, SQLite local state, deterministic policy/session handling, advisory-only AI recommendations, snap/image assets, and a browser admin console for manual operation.

## Features

- Gateway: nftables firewall, NAT, VLAN trunking, captive redirect hooks, and rollback snapshots.
- AAA: FreeRADIUS config generation for PAP, accounting, PEAP, TTLS, EAP templates, upstream RADIUS proxy mode, per-upstream `Status-Server` health insight, reply-attribute mapping, interim accounting, and CoA/disconnect handling for external AAA systems.
- Wireless appliance mode: hostapd config generation and publish flow for open, captive portal, WPA2-Personal, WPA2-Enterprise, WPA3-Personal, and WPA3-Enterprise SSIDs on supported Ubuntu hardware.
- Captive portal: username/password and voucher flows with rate limiting, optional brokered RADIUS auth, and local break-glass fallback.
- Admin API: CRUD for VLANs, portal profiles, users, vouchers, roles, bandwidth profiles, policies, identity sources, RADIUS clients, sessions, alerts, revisions, backups, and AI recommendations.
- Admin UI: operational pages for every admin API object plus a guided `Access Settings` console for portal, LDAP, EAP, upstream AAA, radio, and SSID management, and a live dashboard for appliance, broker, and per-upstream AAA health.
- Runtime enforcement: immediate gateway quarantine for sessions reclassified into quarantine role, Filter-Id, or VLAN 99, live per-session bandwidth shaping from active bandwidth profiles, and immediate session termination when CoA tightens timeouts or requests VLAN reassignment.
- State: pure-Go SQLite driver for CGO-free builds and reproducible tests.
- AI engine: local AI Lite checks for small hardware and full OpenAI-compatible analysis for high-capacity appliances; authentication and traffic admission do not depend on AI.

## Production Readiness

The codebase is ready for pilot production packaging after site-specific secrets, TLS certificates, AP/RADIUS client secrets, and deployment-specific network values are installed.

See [Production Readiness Update](docs/production-readiness-update.md), [Ubuntu Appliance Deployment](docs/ubuntu-appliance-deployment.md), [Ubuntu VM Deployment And Full Flow Test Runbook](docs/ubuntu-vm-runbook.md), [VMware Workstation 17 Player Full Product Runbook](docs/vmware-workstation-17-player-full-test.md), [Hardware Sizing And Deployment Matrix](docs/hardware-sizing-and-deployment-matrix.md), [Deployment Profiles](docs/deployment-profiles.md), [Full AI Engine](docs/full-ai-engine.md), [Wireless Access And UI Guide](docs/wireless-access-ui-guide.md), [External AAA Product Mode](docs/external-aaa-product-mode.md), [AAA Product Implementation Notes](docs/aaa-product-implementation-notes.md), [Operations](docs/operations.md), [Security](docs/security.md), and [Backup/Restore](docs/backup-restore.md).

For a GitHub-clone-inside-VM fast path, run:

```bash
chmod +x scripts/ubuntu-vm-bootstrap.sh
./scripts/ubuntu-vm-bootstrap.sh
```

## Quick Start

```powershell
Copy-Item configs\config.example.yaml configs\config.yaml
go build ./...
go run ./cmd/aegis-admin migrate --config configs/config.yaml
$env:AEGIS_ADMIN_BOOTSTRAP_TOKEN='replace-with-a-long-random-token'
go run ./cmd/aegis-admin seed --config configs/config.yaml
go run ./cmd/aegis-admin-api run --config configs/config.yaml
```

Build the admin UI:

```powershell
cd web/admin-ui
npm ci
npm run build
```

The admin API listens on `admin_port` from the config. The seed command creates a hashed bootstrap API token from `AEGIS_ADMIN_BOOTSTRAP_TOKEN`; if the variable is not set, it prints a generated one-time value.

For physical Wi-Fi appliance builds, install `hostapd`, then use the `Access Settings` page in the admin UI to save appliance settings, preview the generated hostapd config, and write it to the configured path. For live bandwidth enforcement on the gateway, make sure the appliance has Linux `tc` support and the `ifb` kernel module available.

## License

Copyright (c) 2026 Bikram Maity.

This project is licensed for non-commercial use only under the PolyForm Noncommercial License 1.0.0. See [LICENSE](LICENSE).

Commercial use is not permitted without a separate commercial license from the copyright holder.
