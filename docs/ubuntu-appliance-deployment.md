# Ubuntu Appliance Deployment Guide

This guide explains how to deploy AegisNAS as an Ubuntu-based appliance in two product forms:

- an Ubuntu virtual machine that you ship as a ready-to-run appliance image
- a physical Ubuntu server on NAS-class hardware

The same software layout is used in both cases. The only real difference is how the two network interfaces are presented by the platform.

For profile-based tuning across low-power hardware, higher-capacity appliances, and VM builds, also see [Deployment Profiles](deployment-profiles.md). For a single end-to-end VM bring-up and acceptance test path, use [Ubuntu VM Deployment And Full Flow Test Runbook](ubuntu-vm-runbook.md).

If you clone the repo directly inside an Ubuntu VM, you can also use the one-command bootstrap path:

```bash
chmod +x scripts/ubuntu-vm-bootstrap.sh
./scripts/ubuntu-vm-bootstrap.sh
```

That path builds from the current Git checkout, installs the payload, writes a VM-ready config, and starts the services.

## Scope

AegisNAS is currently a network-control appliance: gateway, captive portal, RADIUS, policy, session tracking, telemetry, and admin UI.

It can now also operate as a standards-based AAA edge appliance in front of external RADIUS systems. In that model, AegisNAS is the product-facing NAS and FreeRADIUS broker, while the upstream AAA platform remains the identity authority.

It is not yet a full file-serving NAS stack by itself. If you want SMB, NFS, ZFS, or RAID data services on the same physical box, add those separately and keep their management and storage paths clearly separated from the AegisNAS gateway role.

## Product Model

Treat the product as an appliance with these parts:

- Ubuntu Server LTS base OS
- AegisNAS binaries under `/opt/aegisnas/bin`
- built admin UI under `/opt/aegisnas/admin-ui`
- main config at `/etc/aegisnas/config.yaml`
- runtime data at `/var/lib/aegisnas`
- `systemd` units for all services

For enterprise deployments, add one more logical part:

- an external AAA tier reached through the local FreeRADIUS proxy on the appliance

Recommended topology:

- `WAN` NIC: upstream network, internet, core router, or management uplink
- `LAN` NIC: downstream switch, APs, captive portal clients, or lab network

Default management plane in the sample config:

- admin UI and admin API: `http://<lan-gateway-ip>:8083`
- captive portal: `http://<lan-gateway-ip>:8081`

## When To Use Each Form

### Ubuntu VM Appliance

Use this when you want:

- quick demos
- lab deployments
- customer trials
- easy snapshot, clone, and rollback behavior
- shipping a virtual appliance into VMware, Hyper-V, Proxmox, or KVM environments

### Physical Ubuntu Server Appliance

Use this when you want:

- dedicated edge deployment
- real inline gateway behavior
- direct attachment to APs and switches
- appliance-style product delivery on a mini-PC, x86 server, or NAS-class hardware

## Recommended Sizing

### Minimum

- 2 vCPU or 2 physical cores
- 4 GB RAM
- 40 GB SSD
- 2 NICs

### Recommended For Pilot Production

- 4 cores
- 8 GB RAM
- 120 GB SSD
- 2 Intel or Realtek NICs with stable Linux support
- separate backup storage or remote backup target

### For Physical NAS-Class Hardware

- SSD for OS and database
- optional second SSD or HDD set for logs, backups, or other product data
- UPS if deployed as a branch appliance

## Network Design

The repo's example configuration uses `two-nic` mode:

- `wan.name = eth0`
- `lan.name = eth1`
- `lan.address = 192.168.50.1/24`
- `portal.listen_ip = 192.168.50.1`

Before production use, update these values for your site.

Example downstream plan:

- management and client edge on `192.168.50.0/24`
- captive portal and admin UI on `192.168.50.1`
- DHCP range `192.168.50.100-192.168.50.200`

If you need VLAN trunking instead of simple two-NIC mode, switch `mode` to `trunk` and define VLANs accordingly.

## Build Host Preparation

Build on a Linux workstation or on Windows with a Linux-compatible Go and Node workflow.

Required build tools:

- Go
- Node.js
- npm

Build the backend binaries:

```bash
mkdir -p release/bin
go build -o release/bin/aegis-admin ./cmd/aegis-admin
go build -o release/bin/aegis-admin-api ./cmd/aegis-admin-api
go build -o release/bin/aegis-ai-lite ./cmd/aegis-ai-lite
go build -o release/bin/aegis-gateway ./cmd/aegis-gateway
go build -o release/bin/aegis-policy ./cmd/aegis-policy
go build -o release/bin/aegis-portal ./cmd/aegis-portal
go build -o release/bin/aegis-radius ./cmd/aegis-radius
go build -o release/bin/aegis-session ./cmd/aegis-session
go build -o release/bin/aegis-telemetry ./cmd/aegis-telemetry
```

Build the admin UI:

```bash
cd web/admin-ui
npm ci
npm run build
cd ../..
```

Prepare a release folder:

```bash
mkdir -p release/admin-ui
cp -a web/admin-ui/dist/. release/admin-ui/
cp configs/config.example.yaml release/config.yaml
```

At this point the `release/` folder is your manual product payload.

## Target OS Preparation

Install Ubuntu Server on the target VM or physical appliance.

Use:

- Ubuntu Server LTS
- one disk for OS and runtime data
- two configured NICs

Install runtime packages:

```bash
sudo apt-get update
sudo apt-get install -y \
  ca-certificates \
  curl \
  dnsmasq \
  freeradius \
  freeradius-ldap \
  freeradius-utils \
  hostapd \
  iproute2 \
  jq \
  kmod \
  nftables \
  sqlite3
```

For virtual machines, also install:

```bash
sudo apt-get install -y qemu-guest-agent
```

## Install Layout On The Target

Create directories:

```bash
sudo mkdir -p /opt/aegisnas/bin
sudo mkdir -p /opt/aegisnas/admin-ui
sudo mkdir -p /etc/aegisnas
sudo mkdir -p /var/lib/aegisnas
```

Copy the release payload:

```bash
sudo cp -a release/bin/. /opt/aegisnas/bin/
sudo cp -a release/admin-ui/. /opt/aegisnas/admin-ui/
sudo cp release/config.yaml /etc/aegisnas/config.yaml
```

Make binaries executable:

```bash
sudo chmod 0755 /opt/aegisnas/bin/*
sudo chmod 0640 /etc/aegisnas/config.yaml
```

## Configure The Appliance

Edit the config:

```bash
sudo nano /etc/aegisnas/config.yaml
```

At minimum, set these correctly:

- `wan.name`
- `lan.name`
- `lan.address`
- `lan.gateway`
- `lan.dhcp_range`
- `portal.listen_ip`
- `radius.secret`
- `radius.clients`
- `radius.upstream.*` if external AAA mode is enabled
- `ldap.*` if LDAP is enabled
- `wireless.*` if the appliance itself will broadcast Wi-Fi

Example:

```yaml
mode: two-nic

wan:
  name: enp1s0
  dhcp: true

lan:
  name: enp2s0
  dhcp: false
  address: 192.168.50.1/24
  gateway: 192.168.50.1
  dhcp_range: "192.168.50.100,192.168.50.200,12h"

portal:
  enabled: true
  port: 8081
  listen_ip: "192.168.50.1"
  branding: "AegisNAS Guest WiFi"
  success_url: "https://example.com/success"
  logout_url: "https://example.com/logout"

admin_port: 8083
```

If the product is acting as a NAS appliance in front of external AAA, add:

```yaml
radius:
  secret: "replace-this-radius-secret"
  nas_identifier: "aegisnas-edge-01"
  request_timeout_seconds: 5
  interim_update_seconds: 300
  dynamic_auth:
    enabled: true
    port: 3799
  upstream:
    enabled: true
    realm: "aegis-upstream"
    pool_strategy: "fail-over"
    status_check: "status-server"
    response_window: 20
    zombie_period: 40
    revive_interval: 120
    check_interval: 30
    num_answers_to_alive: 3
    strip_realm: false
    servers:
      - name: "primary-aaa"
        address: "10.10.10.10"
        auth_port: 1812
        acct_port: 1813
        secret: "replace-this-upstream-secret"

portal:
  radius_auth: true
  local_fallback: true
```

Keep APs and switches pointed at AegisNAS, not directly at the upstream AAA system.

If you want `Filter-Id` or VLAN replies to map into local roles and bandwidth profiles, enable and customize the seeded `radius-upstream` identity source. See [External AAA Product Mode](external-aaa-product-mode.md) for the JSON shape.

If you want live per-session bandwidth shaping on the appliance, make sure the configured downstream interface is correct and the host can load the `ifb` kernel module used for ingress shaping.

If the appliance will broadcast Wi-Fi locally, also define:

```yaml
wireless:
  enabled: true
  country_code: "US"
  interface: "wlan0"
  driver: "nl80211"
  hw_mode: "g"
  channel: 6
  beacon_interval: 100
  wmm_enabled: true
  ht_enabled: true
  ctrl_interface: "/var/run/hostapd"
  hostapd_config_path: "/etc/hostapd/hostapd.conf"
  ssids:
    - name: "Aegis Guest"
      auth_mode: "captive-portal"
      bridge: "br-guest"
      client_isolation: true
      portal_profile: "default-guest"
      bandwidth_profile: "guest-default"
    - name: "Aegis Corp"
      auth_mode: "wpa2-enterprise"
      bridge: "br-corp"
      dynamic_vlan: true
      identity_source: "radius-upstream"
```

You can either set these values directly in YAML or manage them from the `Access Settings` page in the admin UI.

## Environment File

Create `/etc/default/aegisnas`:

```bash
sudo tee /etc/default/aegisnas >/dev/null <<'EOF'
AEGIS_ADMIN_UI_DIR=/opt/aegisnas/admin-ui
AEGIS_ADMIN_ALLOWED_ORIGINS=http://192.168.50.1:8083
AEGIS_REVISION_SIGNING_KEY=replace-with-a-long-random-key
EOF
```

Then secure it:

```bash
sudo chmod 0640 /etc/default/aegisnas
```

## Initialize The Database

Set the bootstrap admin token before seeding:

```bash
export AEGIS_ADMIN_BOOTSTRAP_TOKEN="$(openssl rand -hex 32)"
```

Validate, migrate, and seed:

```bash
sudo /opt/aegisnas/bin/aegis-admin validate-config --config /etc/aegisnas/config.yaml
sudo /opt/aegisnas/bin/aegis-admin migrate --config /etc/aegisnas/config.yaml
sudo /opt/aegisnas/bin/aegis-admin seed --config /etc/aegisnas/config.yaml
```

Record the bootstrap output and token in your deployment record.

## Systemd Units

Create the unit files below.

### `aegis-gateway.service`

```ini
[Unit]
Description=AegisNAS Gateway
Wants=network-online.target
After=network-online.target dnsmasq.service

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-gateway run --config /etc/aegisnas/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### `aegis-radius.service`

```ini
[Unit]
Description=AegisNAS RADIUS Manager
Wants=network-online.target
After=network-online.target freeradius.service

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-radius run --config /etc/aegisnas/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### `aegis-portal.service`

```ini
[Unit]
Description=AegisNAS Captive Portal
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-portal run --config /etc/aegisnas/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### `aegis-session.service`

```ini
[Unit]
Description=AegisNAS Session Service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-session run --config /etc/aegisnas/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### `aegis-policy.service`

```ini
[Unit]
Description=AegisNAS Policy Service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-policy run --config /etc/aegisnas/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### `aegis-admin-api.service`

```ini
[Unit]
Description=AegisNAS Admin API
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-admin-api run --config /etc/aegisnas/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### `aegis-ai-lite.service`

```ini
[Unit]
Description=AegisNAS AI Lite
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-ai-lite run --config /etc/aegisnas/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### `aegis-telemetry.service`

```ini
[Unit]
Description=AegisNAS Telemetry
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-telemetry run --config /etc/aegisnas/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Write them under `/etc/systemd/system/`, then enable them:

```bash
sudo systemctl daemon-reload
sudo systemctl enable dnsmasq freeradius hostapd nftables
sudo systemctl enable aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api aegis-ai-lite aegis-telemetry
sudo systemctl restart dnsmasq freeradius
sudo systemctl restart aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api aegis-ai-lite aegis-telemetry
```

If the appliance has a real Wi-Fi radio and `wireless.enabled: true`, write the generated hostapd config and then restart hostapd:

```bash
sudo systemctl restart hostapd
sudo systemctl status hostapd --no-pager
```

## First Validation

Check service status:

```bash
systemctl status aegis-admin-api
systemctl status aegis-gateway
systemctl status aegis-radius
```

Check health endpoints:

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8083/health
curl http://127.0.0.1:8085/health
curl http://127.0.0.1:8086/health
curl http://127.0.0.1:8087/health
```

Open the admin UI from the management side:

```text
http://192.168.50.1:8083
```

Then verify from the UI:

- dashboard service health is green or intentionally disabled
- dashboard upstream AAA cards show each configured home server as reachable, or explain why probing is disabled
- dashboard runtime shaping card shows the correct downstream interface and shaped session count
- access settings page loads
- RADIUS clients list loads
- token login works
- VLAN list loads
- users list loads
- alerts page loads
- staged validate/apply works
- config revision list loads

If the appliance is acting as the Wi-Fi AP, continue with [Wireless Access And UI Guide](wireless-access-ui-guide.md) to finish the SSID and portal setup from the admin console.

## Ubuntu VM Product Flow

Use this when you want to ship the product as a VM image.

### Hypervisor Layout

- NIC 1: bridged or upstream network
- NIC 2: host-only, isolated, or downstream lab network
- disk: thin provisioned is fine for trials, fixed provisioned is better for production

### VM Golden Image Process

1. Install Ubuntu Server.
2. Install runtime packages.
3. Copy AegisNAS binaries, UI, config, and units.
4. Run `validate-config`, `migrate`, and optionally `seed`.
5. Shut the VM down cleanly.
6. Snapshot, clone, or export the VM as the product image.

For reusable customer images, prefer:

- OS installed
- packages installed
- binaries and UI copied
- units installed
- config templated
- no customer secrets baked in

Then perform final commissioning per customer site after first boot.

## Physical Server Product Flow

Use this when you want to ship a hardware appliance.

### Recommended Physical Layout

- WAN NIC to upstream router or switch
- LAN NIC to downstream switch or AP segment
- SSD for OS and AegisNAS runtime
- optional separate storage for backups and non-AegisNAS data

### Physical Appliance Build Process

1. Install Ubuntu Server to the appliance SSD.
2. Install packages and AegisNAS payload exactly as above.
3. Apply your hardware-specific BIOS settings.
4. Label ports clearly as `WAN` and `LAN`.
5. Create a post-install backup or block image.

If you want to replicate many identical appliances, build one reference unit, validate it, then clone the disk image and re-key each unit during commissioning.

## Commissioning Checklist

Run this before handing the product to a user or customer:

1. Change `radius.secret`
2. Change all default RADIUS client secrets
3. Set `AEGIS_ADMIN_ALLOWED_ORIGINS` to the exact management URL
4. Set `AEGIS_REVISION_SIGNING_KEY`
5. Set a new bootstrap token and rotate it after first login
6. Validate DHCP on the LAN side
7. Confirm captive portal redirect on the LAN side
8. Confirm RADIUS auth and accounting
9. Confirm `CoA-Request` / `Disconnect-Request` reach UDP `3799`
10. Export a config backup
11. Record the final IP plan, secrets owner, and rollback procedure

## Update Process

For a field upgrade:

1. Export a config backup from the UI.
2. Create a CLI backup.
3. Stop the AegisNAS services.
4. Replace binaries and UI.
5. Run database migration again.
6. Restart the services.
7. Verify health endpoints and UI login.

Example:

```bash
sudo systemctl stop aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api aegis-ai-lite aegis-telemetry
sudo cp -a release/bin/. /opt/aegisnas/bin/
sudo rm -rf /opt/aegisnas/admin-ui/*
sudo cp -a release/admin-ui/. /opt/aegisnas/admin-ui/
sudo /opt/aegisnas/bin/aegis-admin migrate --config /etc/aegisnas/config.yaml
sudo systemctl start aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api aegis-ai-lite aegis-telemetry
```

## Operations References

Use these alongside this guide:

- [Operations](operations.md)
- [Security](security.md)
- [Backup and Restore](backup-restore.md)
- [Production Readiness Update](production-readiness-update.md)
- [External AAA Product Mode](external-aaa-product-mode.md)
- [AAA Product Implementation Notes](aaa-product-implementation-notes.md)
- [Wireless Access And UI Guide](wireless-access-ui-guide.md)
## Production Vendor Identity

The appliance may ship with lab PEN 55555, but product VSAs are not production-ready in that state. After IANA assignment, use the authenticated Vendor Identity preview/apply workflow; do not edit the PEN directly. The apply operation atomically updates config, installs the generated dictionary, validates FreeRADIUS, restarts it, and records evidence. Confirm `production_verified` before device certification. See `vendor-identity.md`.

Verify `make test-attribute-registry` during image assembly and confirm the production-readiness `attribute_registry` check passes after deployment. Every HA node in one cluster must run the same registry source hash.
