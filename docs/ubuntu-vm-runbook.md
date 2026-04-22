# Ubuntu VM Deployment And Full Flow Test Runbook

This runbook is the complete step-by-step guide for running AegisNAS in an Ubuntu VM and testing the main product flows from the admin UI, portal, RADIUS, EAP, LDAP, backup, and AAA paths.

Use this guide when you want:

- a lab or proof-of-concept deployment
- a customer trial VM
- a repeatable QA and acceptance test path
- a documented bring-up process for future reference

Use this guide together with:

- [Ubuntu Appliance Deployment](ubuntu-appliance-deployment.md)
- [VMware Workstation 17 Player Full Product Runbook](vmware-workstation-17-player-full-test.md)
- [Deployment Profiles](deployment-profiles.md)
- [Login And Captive Portal Test Runbook](login-test-runbook.md)
- [Wireless Access And UI Guide](wireless-access-ui-guide.md)
- [External AAA Product Mode](external-aaa-product-mode.md)

## What This VM Guide Covers

This guide covers:

1. building the product payload
2. creating the Ubuntu VM
3. installing AegisNAS on the VM
4. starting all services
5. logging in to the admin UI
6. testing the main manual UI flows
7. testing captive portal, vouchers, LDAP, upstream AAA, EAP, CoA, backup, rollback, and session handling

Important platform reality:

- A VM can run the product cleanly as a gateway, portal, AAA broker, session engine, and admin appliance.
- A VM does not magically become a real Wi-Fi radio.
- For real SSID broadcasting and EAP client join tests, use an external AP pointed at the VM, or use PCI or USB Wi-Fi passthrough.

## Fast Path From GitHub

If you cloned the repo directly inside the Ubuntu VM, you can bootstrap the full product stack with one command:

```bash
chmod +x scripts/ubuntu-vm-bootstrap.sh
./scripts/ubuntu-vm-bootstrap.sh
```

What the bootstrap script does:

- installs the Ubuntu runtime packages
- installs Go 1.25 and Node.js 20 if needed
- auto-detects `WAN` and `LAN` interfaces
- writes a VM-friendly netplan file unless you skip that step
- runs `go test`
- builds all Go services and the admin UI
- installs the payload under `/opt/aegisnas`
- writes `/etc/aegisnas/config.yaml`
- writes `/etc/default/aegisnas`
- installs the `systemd` units
- validates config, migrates, seeds, enables, and restarts services

Useful variants:

```bash
./scripts/ubuntu-vm-bootstrap.sh --wan ens160 --lan ens192
./scripts/ubuntu-vm-bootstrap.sh --profile lite
./scripts/ubuntu-vm-bootstrap.sh --skip-netplan
./scripts/ubuntu-vm-bootstrap.sh --force-config
```

After the bootstrap completes, continue at `Step 11` in this runbook for health checks, login, and full-flow validation.

## Target Outcome

At the end of this runbook you should have:

- a running Ubuntu VM with AegisNAS services under `systemd`
- an admin UI reachable on `http://<lan-ip>:8083`
- a captive portal reachable on `http://<lan-ip>:8081`
- a validated config and database
- a repeatable acceptance checklist for the major product flows

## Recommended VM Shape

Use the `virtual` deployment form and one of these profiles:

- `branch` for the standard balanced VM path
- `lite` for constrained VM labs
- `enterprise` for higher-capacity virtual test rigs

Recommended VM baseline:

- 4 vCPU
- 8 GB RAM
- 120 GB SSD
- 2 vNICs

Recommended NIC design:

- `WAN` vNIC: bridged or NAT toward the upstream network
- `LAN` vNIC: host-only, internal, or isolated lab segment used for portal and client-side testing

## Tested Product Shape In A VM

In a VM, the cleanest product pattern is:

```text
Client or AP -> LAN side -> AegisNAS VM -> WAN side -> upstream network or AAA
```

Typical use:

- AegisNAS handles portal, RADIUS, policy, session tracking, accounting, and admin UI
- external APs or switches point their RADIUS traffic at the VM
- local Wi-Fi inside the VM stays disabled unless passthrough hardware exists

## Step 1: Prepare The Build Host

On the build machine, make sure these are available:

- Go
- Node.js
- npm
- a way to copy files into the VM, such as `scp`, WinSCP, shared folder, or mounted ISO

From the repo root:

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

Prepare the release payload:

```bash
mkdir -p release/admin-ui
cp -a web/admin-ui/dist/. release/admin-ui/
cp configs/config.example.yaml release/config.yaml
```

## Step 2: Create The Ubuntu VM

Create a new VM using Ubuntu Server 24.04 LTS.

Use:

- generation or firmware type supported by your hypervisor
- 2 network adapters
- 40 GB minimum disk, 120 GB preferred

Network guidance:

- VMware: use one bridged or NAT network and one host-only or custom lab network
- Hyper-V: use one external switch and one internal switch
- Proxmox/KVM: use one uplink bridge and one isolated bridge

Guest OS:

- Ubuntu Server 24.04 LTS
- OpenSSH server enabled during install if you want remote shell access

## Step 3: Install Ubuntu Packages In The VM

After the VM boots:

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
  qemu-guest-agent \
  sqlite3
```

Enable the guest agent if your hypervisor uses it:

```bash
sudo systemctl enable --now qemu-guest-agent
```

## Step 4: Copy The Product Payload Into The VM

Create the target directories:

```bash
sudo mkdir -p /opt/aegisnas/bin
sudo mkdir -p /opt/aegisnas/admin-ui
sudo mkdir -p /etc/aegisnas
sudo mkdir -p /var/lib/aegisnas
```

Copy your built release payload into the VM, then place it here:

```bash
sudo cp -a release/bin/. /opt/aegisnas/bin/
sudo cp -a release/admin-ui/. /opt/aegisnas/admin-ui/
sudo cp release/config.yaml /etc/aegisnas/config.yaml
sudo chmod 0755 /opt/aegisnas/bin/*
sudo chmod 0640 /etc/aegisnas/config.yaml
```

## Step 5: Identify The VM NIC Names

Inside the VM:

```bash
ip -br link
ip -br addr
```

Write down:

- the upstream NIC name, such as `ens160`
- the downstream NIC name, such as `ens192`

You will use those names in `/etc/aegisnas/config.yaml`.

## Step 6: Configure The Product For VM Use

Edit the config:

```bash
sudo nano /etc/aegisnas/config.yaml
```

For a standard VM deployment, start with this pattern:

```yaml
mode: two-nic

deployment:
  profile: branch
  form: virtual
  hardware:
    memory_mb: 8192
    cpu_cores: 4
    prefer_external_ap: true

wan:
  name: ens160
  dhcp: true

lan:
  name: ens192
  dhcp: false
  address: 192.168.50.1/24
  gateway: 192.168.50.1
  dhcp_range: "192.168.50.100,192.168.50.200,12h"

admin_port: 8083

portal:
  enabled: true
  port: 8081
  listen_ip: "192.168.50.1"
  branding: "AegisNAS VM Lab"
  success_url: "https://example.com/success"
  logout_url: "https://example.com/logout"
  radius_auth: false
  local_fallback: true

telemetry:
  enabled: true
  prometheus_port: 9090

ailite:
  enabled: true
  recommendation_limit: 100

policy:
  default_role: guest-basic
  runtime_shaping_enabled: true

radius:
  secret: "replace-this-radius-secret"
  auth_port: 1812
  acct_port: 1813
  max_sessions: 1024
  cert_dir: /etc/freeradius/3.0/certs
  nas_identifier: "aegisnas-vm-edge-01"
  request_timeout_seconds: 5
  interim_update_seconds: 300
  dynamic_auth:
    enabled: true
    port: 3799
  eap:
    default_type: peap
    peap_inner: mschapv2
    ttls_inner: mschapv2
    tls_min_version: "1.2"
    tls_max_version: "1.3"
  clients:
    - ip: 127.0.0.1
      secret: "replace-this-radius-secret"
      shortname: "localhost"
  upstream:
    enabled: false
    realm: "aegis-upstream"
    pool_strategy: "fail-over"
    status_check: "status-server"
    response_window: 20
    zombie_period: 40
    revive_interval: 120
    check_interval: 30
    num_answers_to_alive: 3
    strip_realm: false
    servers: []

wireless:
  enabled: false
  interface: wlan0
  driver: nl80211
  country_code: US
  hostapd_config_path: /etc/hostapd/hostapd.conf
  ssids: []
```

For a constrained VM:

- set `deployment.profile: lite`
- set `telemetry.enabled: false`
- set `ailite.enabled: false`
- set `policy.runtime_shaping_enabled: false`

## Step 7: Create The Environment File

```bash
sudo tee /etc/default/aegisnas >/dev/null <<'EOF'
AEGIS_ADMIN_BOOTSTRAP_TOKEN=replace-with-a-long-random-token
EOF
sudo chmod 0640 /etc/default/aegisnas
```

Use a long random value in production or serious labs.

## Step 8: Validate The Config And Initialize The Database

Run:

```bash
sudo /opt/aegisnas/bin/aegis-admin validate-config --config /etc/aegisnas/config.yaml
sudo /opt/aegisnas/bin/aegis-admin migrate --config /etc/aegisnas/config.yaml
sudo --preserve-env=AEGIS_ADMIN_BOOTSTRAP_TOKEN /opt/aegisnas/bin/aegis-admin seed --config /etc/aegisnas/config.yaml
```

If you are using `/etc/default/aegisnas`, load it into the shell first:

```bash
set -a
. /etc/default/aegisnas
set +a
```

## Step 9: Install The `systemd` Units

Create these units under `/etc/systemd/system/`.

### `aegis-gateway.service`

```ini
[Unit]
Description=AegisNAS Gateway
After=network-online.target dnsmasq.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-gateway run --config /etc/aegisnas/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

### `aegis-radius.service`

```ini
[Unit]
Description=AegisNAS RADIUS Broker
After=network-online.target freeradius.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-radius run --config /etc/aegisnas/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

### `aegis-portal.service`

```ini
[Unit]
Description=AegisNAS Portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-portal run --config /etc/aegisnas/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

### `aegis-session.service`

```ini
[Unit]
Description=AegisNAS Session Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-session run --config /etc/aegisnas/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

### `aegis-policy.service`

```ini
[Unit]
Description=AegisNAS Policy Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-policy run --config /etc/aegisnas/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

### `aegis-admin-api.service`

```ini
[Unit]
Description=AegisNAS Admin API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-admin-api run --config /etc/aegisnas/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

### `aegis-ai-lite.service`

```ini
[Unit]
Description=AegisNAS AI Lite
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-ai-lite run --config /etc/aegisnas/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

### `aegis-telemetry.service`

```ini
[Unit]
Description=AegisNAS Telemetry
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/aegisnas
ExecStart=/opt/aegisnas/bin/aegis-telemetry run --config /etc/aegisnas/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

## Step 10: Enable And Start Services

```bash
sudo systemctl daemon-reload
sudo systemctl enable dnsmasq freeradius nftables
sudo systemctl enable aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api aegis-ai-lite aegis-telemetry
sudo systemctl restart dnsmasq freeradius nftables
sudo systemctl restart aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api aegis-ai-lite aegis-telemetry
```

If `telemetry.enabled: false` or `ailite.enabled: false`, the services may exit immediately by design. That is fine.

## Step 11: Verify Basic Health

Run:

```bash
systemctl --no-pager --full status aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8083/health
curl -fsS http://127.0.0.1:8081/health
```

Also verify the LAN IP is present:

```bash
ip -br addr show
```

From the host or another LAN-side client, open:

```text
http://192.168.50.1:8083
```

Replace `192.168.50.1` with your actual configured LAN IP.

## Step 12: First Login To The Admin UI

Use the bootstrap token created by seeding.

After login, confirm these pages load:

- `Dashboard`
- `Access Settings`
- `RADIUS Clients`
- `Users`
- `Vouchers`
- `Roles`
- `Bandwidth Profiles`
- `Policies`
- `Identity Sources`
- `Portal Profiles`
- `Sessions`
- `Alerts`
- `Config Revisions`
- `Backups`
- `AI Recommendations`

## Step 13: Configure The VM Profile In The UI

Go to `Access Settings`.

Set:

- `Profile`: `Branch` or `Lite`
- `Form`: `Virtual Appliance`
- memory and CPU values to match the actual VM
- `Prefer External AP`: on

Then click:

- `Apply Profile Defaults`
- review the toggles
- `Save Settings`

This is the cleanest way to align the VM with the new deployment profile model.

## Step 14: Test The Core Admin Flows

These are fully UI-driven and should work entirely in the VM.

### 14.1 VLAN CRUD

1. open `VLANs`
2. add a VLAN
3. edit the VLAN
4. delete the VLAN
5. apply staged changes

Pass condition:

- the table updates
- the change appears in `Config Revisions`

### 14.2 Roles CRUD

1. open `Roles`
2. add a role with optional VLAN and bandwidth profile
3. edit it
4. delete it
5. apply staged changes

Pass condition:

- rows stage and apply correctly
- no backend errors appear

### 14.3 Bandwidth Profiles CRUD

1. open `Bandwidth Profiles`
2. create a test profile
3. edit it
4. delete it
5. apply staged changes

### 14.4 Portal Profiles CRUD

1. open `Portal Profiles`
2. create a test portal profile
3. edit branding and URLs
4. delete it
5. apply staged changes

### 14.5 Identity Sources CRUD

1. open `Identity Sources`
2. create a disabled LDAP source
3. create a disabled RADIUS mapping source
4. edit the JSON
5. delete the test entries
6. apply staged changes

### 14.6 Policies CRUD

1. open `Policies`
2. create a rule
3. edit the JSON conditions
4. set VLAN, bandwidth, timeout, or portal fields
5. delete the rule
6. apply staged changes

### 14.7 Users CRUD

1. open `Users`
2. create a local portal test user
3. edit the role
4. optionally update the password
5. delete only after portal testing is complete

### 14.8 Vouchers CRUD

1. open `Vouchers`
2. create a voucher with:
   - code
   - role
   - duration
   - usage limit
   - expiry
3. edit the voucher
4. keep it until voucher testing is complete

### 14.9 RADIUS Clients CRUD

1. open `RADIUS Clients`
2. add a test client entry for:
   - localhost
   - external AP
   - test switch
3. edit and apply

### 14.10 Backups

1. open `Backups`
2. export the config JSON
3. confirm the file downloads
4. re-import that same file

Pass condition:

- export works
- import completes
- config remains valid

### 14.11 Config Revisions

1. make a small change, then apply it
2. open `Config Revisions`
3. confirm a new revision exists
4. roll back to the earlier revision

Pass condition:

- rollback succeeds
- the previous settings return

### 14.12 Sessions And Alerts

1. open `Sessions`
2. confirm the page loads even before users connect
3. open `Alerts`
4. confirm the page loads and acknowledge a test alert if one exists

### 14.13 AI Recommendations

1. open `AI Recommendations`
2. confirm the page loads
3. acknowledge a recommendation if present

## Step 15: Test Captive Portal Local User Flow

This is the simplest client-facing acceptance test.

Prerequisites:

- `portal.enabled: true`
- a local user exists
- LAN-side client can reach the VM LAN network

Steps:

1. connect a client to the LAN-side network
2. browse to:

```text
http://192.168.50.1:8081
```

3. log in with the local test user

Pass condition:

- login succeeds
- a session appears in `Sessions`
- the session shows portal auth
- logout ends the session

If you want a truer captive redirect test:

- place the client behind the downstream side the same way a guest network would be attached
- browse to any HTTP site and confirm you land on the portal

## Step 16: Test Voucher Flow

Prerequisites:

- a voucher exists
- portal is enabled

Steps:

1. open the portal page from a LAN-side client
2. choose the voucher path
3. submit the voucher code

Pass condition:

- access is granted
- a session appears
- voucher usage updates as expected

## Step 17: Test LDAP Flow

Prerequisites:

- reachable LDAP server
- correct bind DN, password, base DN, and filters
- `ldap.enabled: true`

Steps:

1. configure LDAP in `Access Settings`
2. save settings
3. use a valid LDAP username and password on the portal page

Pass condition:

- LDAP login succeeds
- session is created
- role mapping behaves as expected

Negative test:

1. try a bad password
2. confirm login fails

Pass condition:

- no stale session is created

## Step 18: Test Upstream AAA Flow

Prerequisites:

- reachable upstream RADIUS servers
- shared secrets configured
- `radius.upstream.enabled: true`
- `portal.radius_auth: true` if testing portal through the broker

Steps:

1. configure the upstream servers in `Access Settings`
2. save settings
3. click `Apply RADIUS Config`
4. open `Dashboard`
5. confirm upstream server health appears

Then test brokered portal auth:

1. open the portal page
2. log in with a username that should be validated upstream

Pass condition:

- upstream AAA status is visible
- login succeeds
- session appears with mapped role, VLAN, or timeouts if returned by AAA

Useful shell checks:

```bash
sudo journalctl -u freeradius -u aegis-radius -n 100 --no-pager
sudo ls -l /etc/freeradius/3.0/proxy.conf
```

## Step 19: Test RADIUS Device Client Flow

This validates that an AP, switch, or lab RADIUS client can point to the VM.

Prerequisites:

- a test RADIUS client or AP configured to use the VM IP
- matching client secret present in `RADIUS Clients`

Steps:

1. add the device in `RADIUS Clients`
2. apply RADIUS config
3. trigger an authentication request from the device or supplicant

Pass condition:

- request reaches the VM
- device auth succeeds or fails according to policy
- logs show the request path

## Step 20: Test EAP Flow

This is the correct way to test WPA2/WPA3-Enterprise with a VM:

- use an external AP or controller
- point that AP at the AegisNAS VM as RADIUS server
- let the AP broadcast the SSID

Do not expect a plain VM NIC to act as a real access point.

Prerequisites:

- external AP or controller
- AP RADIUS client entry present in AegisNAS
- EAP settings configured

Steps:

1. add or verify the AP in `RADIUS Clients`
2. configure `Access Settings` for EAP and upstream AAA if used
3. click `Apply RADIUS Config`
4. configure the AP SSID for WPA2-Enterprise or WPA3-Enterprise
5. join from a supplicant

Pass condition:

- the client associates through the AP
- auth succeeds through AegisNAS
- the session appears in the VM

## Step 21: Test CoA And Disconnect

Prerequisites:

- `radius.dynamic_auth.enabled: true`
- upstream AAA or test tool can send CoA or Disconnect to the VM

Test cases:

1. `Disconnect-Request`
2. `CoA-Request` with tighter session timeout
3. `CoA-Request` with VLAN change
4. `CoA-Request` with quarantine role or `Filter-Id`

Pass conditions:

- disconnect request ends the session
- tighter timeout can terminate the session immediately if already exceeded
- VLAN change forces reauthentication
- quarantine request moves the session into quarantine behavior

Validation:

- watch `Sessions`
- watch `Dashboard`
- check service logs:

```bash
sudo journalctl -u aegis-session -u aegis-radius -u aegis-gateway -n 200 --no-pager
```

## Step 22: Test Live Bandwidth Shaping

Prerequisites:

- `policy.runtime_shaping_enabled: true`
- a valid downstream interface is configured
- at least one bandwidth profile exists

Steps:

1. create a bandwidth profile in the UI
2. assign it through a role or identity mapping
3. authenticate a client
4. open `Dashboard`

Pass condition:

- shaped session count increases
- runtime shaping status is healthy

Useful shell checks:

```bash
sudo tc qdisc show
sudo tc class show dev <lan-interface>
```

## Step 23: Test Manual Session Termination

Steps:

1. create an active session through portal or EAP
2. open `Sessions`
3. click `Terminate`

Pass condition:

- the session ends
- the client is forced out of the session

## Step 24: Test Backup And Restore Again After Real Usage

After you have real sessions and multiple config objects:

1. export config backup
2. make a visible config change
3. import the earlier backup

Pass condition:

- the prior configuration returns
- core services continue running

## Step 25: Test Rollback Again After Real Usage

1. make a small but visible change
2. apply it
3. open `Config Revisions`
4. roll back

Pass condition:

- earlier settings are restored
- admin UI still loads
- runtime enforcement resyncs cleanly

## Step 26: Full Acceptance Checklist

Mark the VM ready when all of these are true:

- config validates
- database migrates and seeds cleanly
- admin UI is reachable
- portal is reachable
- `Dashboard` loads
- `Access Settings` saves successfully
- `RADIUS Clients` CRUD works
- `Users` CRUD works
- `Vouchers` CRUD works
- `Roles` CRUD works
- `Bandwidth Profiles` CRUD works
- `Policies` CRUD works
- `Identity Sources` CRUD works
- `Portal Profiles` CRUD works
- backup export and import work
- config revisions and rollback work
- local portal login works
- voucher login works
- LDAP login works if LDAP is enabled
- upstream AAA status is visible if upstream AAA is enabled
- brokered portal auth works if `portal.radius_auth` is enabled
- RADIUS device flow works from AP or switch
- EAP works through an external AP if enterprise Wi-Fi is in scope
- CoA and disconnect work if dynamic authorization is in scope
- session termination from the UI works
- runtime shaping works if enabled

## Step 27: Troubleshooting

### Service not starting

```bash
sudo journalctl -u aegis-admin-api -u aegis-gateway -u aegis-portal -u aegis-radius -u aegis-session -u aegis-policy -n 200 --no-pager
```

### Config error

```bash
sudo /opt/aegisnas/bin/aegis-admin validate-config --config /etc/aegisnas/config.yaml
```

### FreeRADIUS config issue

```bash
sudo freeradius -XC
```

### Portal unreachable

Check:

- `portal.listen_ip`
- LAN interface address
- firewall rules
- whether the client is actually on the LAN-side network

### Admin UI unreachable

Check:

- `admin_port`
- service status
- host firewall
- whether the admin UI bundle exists under `/opt/aegisnas/admin-ui`

### Wireless expectations in VM are wrong

Remember:

- plain virtual NICs are not Wi-Fi radios
- use external APs or passthrough hardware for SSID broadcasting tests

## Step 28: Snapshot The VM

After all tests pass:

1. stop the VM cleanly
2. take a hypervisor snapshot or template clone
3. record:
   - config revision
   - deployment profile
   - Ubuntu version
   - test date

That gives you a known-good VM image for future labs and customer trials.
