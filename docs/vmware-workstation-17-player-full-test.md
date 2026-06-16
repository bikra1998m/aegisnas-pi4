# VMware Workstation 17 Player Full Product Runbook

This guide starts after Ubuntu is installed in a VMware Workstation 17 Player VM. It walks through running AegisNAS, checking every service, logging into the admin UI, testing captive portal internet-after-login, testing RADIUS and accounting, capturing logs, and recovering from common lab failures.

Use this guide when you want one repeatable VMware lab process from a fresh Ubuntu VM to a full product test.

For HA pair setup and failover drills, use this guide together with [HA Active/Standby Runbook](ha-active-standby-runbook.md).
For version-aware upgrade rollback package rehearsal and offline recovery, use this guide together with [Upgrade Rollback Runbook](upgrade-rollback-runbook.md).

## 0. Target Lab

Recommended topology:

```text
Internet or upstream LAN
        |
  VMware NAT or Bridged network
        |
  AegisNAS VM - WAN NIC
  AegisNAS VM - LAN NIC 192.168.50.1/24
        |
  VMware host-only or isolated network
        |
  Client VM 192.168.50.x
```

Use two VMs for the real captive portal test:

- `AegisNAS VM`: Ubuntu Server, two NICs
- `Client VM`: Ubuntu Desktop, Windows, or any test OS, one NIC on the same host-only LAN

Important:

- Opening the portal on the AegisNAS VM itself proves the login page works.
- It does not fully prove captive enforcement.
- To prove internet-after-login, test from the client VM behind the AegisNAS LAN side.

## 1. VMware VM Settings

Power off the AegisNAS VM first.

Open:

```text
VMware Player -> select VM -> Edit virtual machine settings
```

Configure:

```text
Memory: 4096 MB minimum, 8192 MB recommended
Processors: 2 minimum, 4 recommended
Hard Disk: 40 GB minimum, 120 GB recommended
Network Adapter 1: NAT or Bridged
Network Adapter 2: Host-only or Custom VMnet used only for the AegisNAS LAN
```

Recommended VMware network choices:

- Use `NAT` for WAN if you want the easiest internet path.
- Use `Bridged` for WAN if your physical LAN gives the VM a normal DHCP address.
- Use `Host-only` or an isolated custom VMnet for LAN.

If VMware DHCP is active on the host-only network, it can race with AegisNAS `dnsmasq`. Best options:

1. Disable VMware DHCP on the host-only VMnet if your VMware install exposes Virtual Network Editor.
2. Use a custom isolated VMnet with DHCP disabled.
3. If you cannot disable VMware DHCP, set the client VM IP manually during captive portal testing.

## 2. Boot Ubuntu And Confirm NIC Names

Log into the AegisNAS Ubuntu VM.

Check network interfaces:

```bash
ip -br addr
ip route
```

Typical VMware names:

```text
ens33  WAN, NAT or bridged
ens37  LAN, host-only
```

Confirm the WAN side has internet:

```bash
ping -c 3 8.8.8.8
getent ahosts github.com
curl -I https://github.com
```

If DNS fails, fix Ubuntu networking before installing AegisNAS.

## 3. Install Basic Ubuntu Tools

```bash
sudo apt-get update
sudo apt-get install -y \
  ca-certificates \
  curl \
  git \
  openssh-server \
  jq \
  net-tools \
  sqlite3 \
  freeradius-utils
```

Optional SSH access from the Windows host:

```bash
sudo systemctl enable --now ssh
hostname -I
```

Then SSH to the WAN IP from Windows PowerShell:

```powershell
ssh bikram@<aegisnas-wan-ip>
```

## 4. Clone Or Update The Product

Fresh clone:

```bash
cd ~
git clone https://github.com/bikra1998m/aegisnas-pi4.git
cd ~/aegisnas-pi4
```

Existing clone:

```bash
cd ~/aegisnas-pi4
git status --short
git pull --ff-only
```

In-place upgrade and smoke test for an already deployed VM:

```bash
cd ~/aegisnas-pi4
git pull --ff-only
sudo bash scripts/ubuntu-vm-upgrade-smoke-test.sh --wan ens33 --lan ens37
```

That path preserves the current VM config, reruns bootstrap without `--force-config`, checks schema migration state, and saves API and health results under `/var/tmp/aegisnas-upgrade-smoke/`.

Before a real VMware upgrade window, rehearse the rollback path too:

```bash
cd ~/aegisnas-pi4
sudo bash scripts/ubuntu-upgrade-rollback-rehearsal.sh
```

That gives you:

- a fresh version-aware rollback package
- inspection output for online versus offline restore
- an extracted package workspace
- a prepared offline restore helper workspace

If you want to dry-run a specific rollback package:

```bash
sudo bash scripts/ubuntu-upgrade-rollback-rehearsal.sh \
  --package /var/tmp/aegisnas-upgrade-rollback.zip
```

For an HA-enabled VMware lab with two Ubuntu VMs, run the HA helper after the upgrade:

```bash
sudo bash scripts/ha-active-standby-smoke-test.sh --role active
sudo bash scripts/ha-active-standby-smoke-test.sh --role standby --stage-shared
sudo bash scripts/ha-active-standby-smoke-test.sh --role standby --stage-shared --activate-latest
```

Then validate the pair from the active VM:

```bash
sudo bash scripts/ha-pair-upgrade-validate.sh
```

If SSH between the pair is available, use:

```bash
sudo bash scripts/ha-pair-upgrade-validate.sh --peer-ssh ubuntu@192.168.50.12
```

Then continue with the failover and recovery steps in [HA Active/Standby Runbook](ha-active-standby-runbook.md). The quickest controlled drill on the active node is:

```bash
sudo bash scripts/ha-failover-drill.sh
```

For repeated HA rehearsal in the VMware lab, run this from the active VM console:

```bash
sudo bash scripts/ha-soak-test.sh --cycles 3
```

If the standby should be staged and activated before the soak begins:

```bash
sudo bash scripts/ha-soak-test.sh --cycles 3 --stage-shared-before-start --activate-latest-before-start
```

Multi-cycle soak runs require `high_availability.preempt: true` so the original active VM can reclaim the VIP between cycles.

If a previous bootstrap changed the script locally and pull fails:

```bash
cd ~/aegisnas-pi4
git restore scripts/ubuntu-vm-bootstrap.sh
git pull --ff-only
```

## 5. Pick A Deployment Profile

Use one of these:

```text
lite        small lab VM, AI and telemetry off
branch      balanced default
enterprise  high CPU or RAM, full AI capable
custom      manual tuning
```

For your earlier VMware shape, this is the safe lab command:

```bash
cd ~/aegisnas-pi4
bash scripts/ubuntu-vm-bootstrap.sh \
  --wan ens33 \
  --lan ens37 \
  --profile lite \
  --skip-netplan \
  --force-config
```

For a stronger VM:

```bash
cd ~/aegisnas-pi4
bash scripts/ubuntu-vm-bootstrap.sh \
  --wan ens33 \
  --lan ens37 \
  --profile branch \
  --skip-netplan \
  --force-config
```

For high-configuration hardware with full AI mode:

```bash
cd ~/aegisnas-pi4
bash scripts/ubuntu-vm-bootstrap.sh \
  --wan ens33 \
  --lan ens37 \
  --profile enterprise \
  --ai-mode full \
  --ai-endpoint https://ai.example.net \
  --ai-model ops-model \
  --skip-netplan \
  --force-config
```

Notes:

- `--skip-netplan` avoids breaking the WAN during a remote SSH session.
- With `--skip-netplan`, the script still applies `192.168.50.1/24` to the LAN interface at runtime.
- If the VM reboots and the LAN IP disappears, rerun the bootstrap command or apply the runtime LAN IP again.
- Use `bash scripts/ubuntu-vm-bootstrap.sh` if `./scripts/ubuntu-vm-bootstrap.sh` gives `Permission denied`.

## 6. What The Bootstrap Does

The bootstrap:

1. installs runtime packages unless skipped
2. installs Go and Node.js if needed
3. applies the LAN runtime IP when `--skip-netplan` is used
4. runs the Go tests
5. builds Go services
6. builds the admin UI
7. stops running AegisNAS services before replacing binaries
8. installs binaries into `/opt/aegisnas/bin`
9. installs the UI into `/opt/aegisnas/admin-ui`
10. writes `/etc/default/aegisnas`
11. writes `/etc/aegisnas/config.yaml`
12. writes systemd units
13. validates config
14. migrates and seeds SQLite
15. writes dnsmasq and FreeRADIUS config
16. starts all services

At the end, it prints:

```text
Admin UI:  http://192.168.50.1:8083
Portal:    http://192.168.50.1:8081
Health:    http://127.0.0.1:8080/health
Bootstrap admin token:
...
```

## 7. Verify Services

Run this from the AegisNAS VM:

```bash
systemctl --no-pager --full status \
  aegis-gateway \
  aegis-radius \
  aegis-portal \
  aegis-session \
  aegis-policy \
  aegis-admin-api \
  dnsmasq \
  freeradius \
  nftables
```

Health checks:

```bash
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8081/health
curl -fsS http://127.0.0.1:8082/health
curl -fsS http://127.0.0.1:8083/health
curl -fsS http://127.0.0.1:8085/health
curl -fsS http://127.0.0.1:8087/health
```

Expected:

```json
{"status":"ok"}
```

Port check:

```bash
sudo ss -ltnup '( sport = :53 or sport = :8080 or sport = :8081 or sport = :8082 or sport = :8083 or sport = :8085 or sport = :8087 )'
```

Expected listeners:

```text
dnsmasq on 192.168.50.1:53
aegis-gateway on :8080
aegis-portal on :8081
aegis-policy on :8082
aegis-admin-api on :8083
aegis-radius on :8085
aegis-session on :8087
```

## 8. Get The Admin Token

Use `sudo` because `/etc/default/aegisnas` is intentionally protected:

```bash
sudo awk -F= '/^AEGIS_ADMIN_BOOTSTRAP_TOKEN=/{print $2}' /etc/default/aegisnas
```

For shell use:

```bash
TOKEN="$(sudo awk -F= '/^AEGIS_ADMIN_BOOTSTRAP_TOKEN=/{print $2}' /etc/default/aegisnas)"
echo "$TOKEN"
```

## 9. Open The Admin UI

From the AegisNAS VM, find the WAN IP:

```bash
hostname -I
```

Open from the Windows host browser:

```text
http://<aegisnas-wan-ip>:8083
```

Or from a LAN-side client:

```text
http://192.168.50.1:8083
```

Sign in with the bootstrap token.

Dashboard checks:

- `Admin API`: ok
- `Gateway`: ok
- `Portal`: ok
- `Policy`: ok
- `RADIUS Broker`: ok
- `Session Service`: ok
- `FreeRADIUS`: ok
- `dnsmasq`: ok
- `nftables`: ok

For `lite` profile, these are expected:

- `AI Engine`: disabled
- `Telemetry`: disabled
- `hostapd`: disabled unless wireless is enabled

If integrations are enabled, also check the dashboard runtime cards for:

- admin SSO
- SIEM export
- controller automation

## 10. Create The Local Captive Portal Test User

In the admin UI:

```text
Users -> Add User
```

Use:

```text
Username: guest1
Password: guest123
Role: guest-basic
Full Name: Guest One
Email: guest1@example.local
```

Save, then apply pending changes if the UI stages the operation.

Confirm the seeded objects exist:

```text
Roles -> guest-basic
Bandwidth Profiles -> 10m-down-5m-up
Portal Profiles -> default-guest
```

If you plan to test the newer runtime paths, also note these operator pages:

```text
Guest Requests
Devices
Admin Access
```

## 11. Manual Portal Page Test On The Same VM

This verifies the portal process and login form.

It does not prove captive internet enforcement.

From the AegisNAS VM:

```bash
curl -i http://127.0.0.1:8081/
```

Manual login with a synthetic MAC:

```bash
curl -i -L \
  -d "client_mac=manual-test-01" \
  -d "username=guest1" \
  -d "password=guest123" \
  http://127.0.0.1:8081/login
```

Check sessions:

```bash
sqlite3 /var/lib/aegisnas/data.db \
  "SELECT username, mac, ip, auth_method, role, bandwidth_profile, end_time FROM sessions ORDER BY start_time DESC LIMIT 5;"
```

Logout:

```bash
curl -i "http://127.0.0.1:8081/logout?client_mac=manual-test-01"
```

## 12. Create The Client VM For Real Internet-After-Login

Create or power on a second VM.

Client VM settings:

```text
Network Adapter 1: same Host-only or Custom VMnet as AegisNAS LAN NIC
No WAN/NAT adapter on the client VM during captive portal testing
```

Boot the client.

If AegisNAS `dnsmasq` wins DHCP, the client should receive:

```text
IP:      192.168.50.100 to 192.168.50.200
Gateway: 192.168.50.1
DNS:     192.168.50.1
```

Linux client checks:

```bash
ip -br addr
ip route
resolvectl status
ping -c 3 192.168.50.1
```

If the client gets a VMware DHCP address instead, set a manual address.

Ubuntu Desktop client with NetworkManager:

```bash
nmcli con show
sudo nmcli con mod "<connection-name>" \
  ipv4.method manual \
  ipv4.addresses 192.168.50.50/24 \
  ipv4.gateway 192.168.50.1 \
  ipv4.dns 192.168.50.1
sudo nmcli con down "<connection-name>"
sudo nmcli con up "<connection-name>"
```

Ubuntu Server temporary manual IP:

```bash
sudo ip addr replace 192.168.50.50/24 dev ens33
sudo ip route replace default via 192.168.50.1 dev ens33
printf 'nameserver 192.168.50.1\n' | sudo tee /etc/resolv.conf
```

Windows client manual IPv4:

```text
IP address: 192.168.50.50
Subnet mask: 255.255.255.0
Default gateway: 192.168.50.1
DNS server: 192.168.50.1
```

## 13. Capture Baseline Logs

From the AegisNAS VM:

```bash
cd ~/aegisnas-pi4
sudo bash scripts/capture-login-debug-logs.sh --scenario prelogin-baseline
```

The bundle is written under:

```text
/var/tmp/aegisnas-login-debug/
```

Each bundle has separate files for:

- service logs
- health checks
- network state
- redacted config
- redacted environment

## 14. Test Captive Portal Login With Internet After Login

From the client VM, open:

```text
http://192.168.50.1:8081
```

From a Windows host browser, `192.168.50.1` only works when `VMware Network Adapter VMnet1` is on the AegisNAS LAN subnet. A typical host-only test adapter should look like:

```text
VMware Network Adapter VMnet1
IP address: 192.168.50.2
Subnet mask: 255.255.255.0
Gateway: blank
DNS: blank
```

Windows PowerShell pre-check:

```powershell
ping 192.168.50.1
Test-NetConnection 192.168.50.1 -Port 8081
```

Log in:

```text
username: guest1
password: guest123
```

After login, test internet from the client:

```bash
curl -I http://neverssl.com
curl -I https://example.com
nslookup example.com 192.168.50.1
ping -c 3 8.8.8.8
```

Admin UI checks:

```text
Sessions -> active guest1 session exists
Dashboard -> Active Sessions increments
Dashboard -> Session Mix shows activity
```

CLI evidence from AegisNAS VM:

```bash
sqlite3 /var/lib/aegisnas/data.db \
  "SELECT username, mac, ip, auth_method, role, bandwidth_profile, vlan, end_time FROM sessions ORDER BY start_time DESC LIMIT 10;"
```

Capture post-login logs:

```bash
cd ~/aegisnas-pi4
sudo bash scripts/capture-login-debug-logs.sh --scenario portal-local-postlogin
```

Pass condition:

- client can reach the portal before login
- `guest1 / guest123` login succeeds
- session appears in the admin UI
- client reaches internet after login
- logs show healthy portal, gateway, session, dnsmasq, and nftables services

## 15. Logout And Confirm Session Ends

From client browser:

```text
http://192.168.50.1:8081/logout?client_mac=<client-mac>
```

If you do not know the MAC, terminate from admin UI:

```text
Sessions -> Terminate
```

Or from SQLite for emergency lab cleanup:

```bash
sqlite3 /var/lib/aegisnas/data.db \
  "UPDATE sessions SET end_time = CURRENT_TIMESTAMP, stop_reason = 'manual-lab-cleanup' WHERE end_time IS NULL;"
sudo systemctl restart aegis-session aegis-gateway
```

Capture logout logs:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario portal-local-logout
```

## 16. Voucher Login Test

Admin UI:

```text
Vouchers -> Add Voucher
```

Example:

```text
Code: TEST-001
Role: guest-basic
Duration Minutes: 1440
Usage Limit: 1
```

From the client VM:

```text
http://192.168.50.1:8081/voucher
```

Enter:

```text
TEST-001
```

Verify:

```text
Sessions -> voucher_TEST-001 session exists
Vouchers -> used count increments
Client internet works after voucher login
```

Capture:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario portal-voucher-success
```

## 17. Local RADIUS Auth Test

Get the local RADIUS shared secret from the config:

```bash
RADIUS_SECRET="$(sudo awk -F': ' '/^  secret:/{gsub(/"/,"",$2); print $2; exit}' /etc/aegisnas/config.yaml)"
echo "$RADIUS_SECRET"
```

Run PAP auth:

```bash
radtest guest1 guest123 127.0.0.1 0 "$RADIUS_SECRET"
```

Expected:

```text
Access-Accept
```

If it fails, check:

```bash
journalctl -u freeradius -n 120 --no-pager
journalctl -u aegis-radius -n 120 --no-pager
```

## 18. Accounting Start, Interim, And Stop Test

Create one session ID:

```bash
ACCT_ID="manual-acct-$(date +%s)"
RADIUS_SECRET="$(sudo awk -F': ' '/^  secret:/{gsub(/"/,"",$2); print $2; exit}' /etc/aegisnas/config.yaml)"
```

Accounting Start:

```bash
cat >/tmp/aegis-acct-start.txt <<EOF
User-Name = "guest1"
NAS-IP-Address = 127.0.0.1
NAS-Identifier = "aegisnas-manual-test"
Acct-Status-Type = Start
Acct-Session-Id = "${ACCT_ID}"
Calling-Station-Id = "02-00-00-00-00-10"
Framed-IP-Address = 192.168.50.50
EOF

radclient -x 127.0.0.1:1813 acct "$RADIUS_SECRET" </tmp/aegis-acct-start.txt
```

Accounting Interim:

```bash
cat >/tmp/aegis-acct-interim.txt <<EOF
User-Name = "guest1"
NAS-IP-Address = 127.0.0.1
NAS-Identifier = "aegisnas-manual-test"
Acct-Status-Type = Interim-Update
Acct-Session-Id = "${ACCT_ID}"
Acct-Input-Octets = 1000
Acct-Output-Octets = 2000
Acct-Session-Time = 60
Calling-Station-Id = "02-00-00-00-00-10"
Framed-IP-Address = 192.168.50.50
EOF

radclient -x 127.0.0.1:1813 acct "$RADIUS_SECRET" </tmp/aegis-acct-interim.txt
```

Accounting Stop:

```bash
cat >/tmp/aegis-acct-stop.txt <<EOF
User-Name = "guest1"
NAS-IP-Address = 127.0.0.1
NAS-Identifier = "aegisnas-manual-test"
Acct-Status-Type = Stop
Acct-Session-Id = "${ACCT_ID}"
Acct-Input-Octets = 1500
Acct-Output-Octets = 3000
Acct-Session-Time = 120
Calling-Station-Id = "02-00-00-00-00-10"
Framed-IP-Address = 192.168.50.50
EOF

radclient -x 127.0.0.1:1813 acct "$RADIUS_SECRET" </tmp/aegis-acct-stop.txt
```

Check service logs:

```bash
journalctl -u freeradius -n 80 --no-pager
journalctl -u aegis-radius -n 80 --no-pager
```

## 19. Dynamic Disconnect Test

Use this only when there is an active session.

Get an active session:

```bash
sqlite3 /var/lib/aegisnas/data.db \
  "SELECT id, username, mac FROM sessions WHERE end_time IS NULL ORDER BY start_time DESC LIMIT 1;"
```

Send a Disconnect-Request by username:

```bash
RADIUS_SECRET="$(sudo awk -F': ' '/^  secret:/{gsub(/"/,"",$2); print $2; exit}' /etc/aegisnas/config.yaml)"

cat >/tmp/aegis-disconnect.txt <<EOF
User-Name = "guest1"
EOF

radclient -x 127.0.0.1:3799 disconnect "$RADIUS_SECRET" </tmp/aegis-disconnect.txt
```

Expected:

```text
Disconnect-ACK
```

Then confirm the session ended in the admin UI.

## 20. Vendor Dictionary Check

Confirm the AegisNAS vendor dictionary was installed:

```bash
sudo sed -n '1,220p' /etc/freeradius/3.0/dictionary.aegisnas
sudo grep -n 'AegisNAS' /etc/freeradius/3.0/dictionary
```

Expected:

```text
VENDOR AegisNAS 55555
ATTRIBUTE AegisNAS-Role ...
ATTRIBUTE AegisNAS-Bandwidth-Profile ...
```

Production note:

- `55555` is a lab placeholder.
- Replace it with your real IANA Private Enterprise Number before production by setting `AEGISNAS_VENDOR_ID` or `radius.vendor.id`.

## 21. External AAA Test

Use this when you have an upstream RADIUS or AAA server.

Admin UI:

```text
Access Settings -> Upstream AAA Servers
```

Set:

```text
Upstream AAA Enabled: on
Realm: aegis-upstream
Pool Strategy: fail-over
Status Check: status-server or none
Server Name: primary-aaa
Address: <aaa-server-ip>
Auth Port: 1812
Acct Port: 1813
Secret: <aaa-shared-secret>
```

Save settings.

Apply FreeRADIUS config:

```text
Access Settings -> Apply RADIUS Config
```

Restart services:

```bash
sudo systemctl restart freeradius aegis-radius aegis-portal aegis-session
```

Test from the portal or with `radtest` using a user that exists on the upstream AAA server.

Check:

```bash
journalctl -u freeradius -n 160 --no-pager
journalctl -u aegis-radius -n 160 --no-pager
```

If upstream returns AegisNAS VSAs, confirm sessions receive the mapped role, VLAN, bandwidth profile, timeout, or quarantine decision.

## 22. LDAP Login Test

Admin UI:

```text
Access Settings -> Captive Portal And Directory
```

Set:

```text
LDAP Enabled: on
LDAP URL: ldaps://ldap.example.com
Base DN: dc=example,dc=com
Bind DN: cn=svc-aegisnas,dc=example,dc=com
Bind Password: <password>
User Filter: (uid=%s)
Group Filter: (memberUid=%s)
```

Save settings and restart:

```bash
sudo systemctl restart aegis-portal aegis-admin-api
```

From the client VM, login at:

```text
http://192.168.50.1:8081
```

Use an LDAP user.

Check:

```text
Sessions -> LDAP-backed session exists
Client internet works after login
```

## 23. EAP Or 802.1X Test With External AP

VMware cannot turn a normal virtual NIC into Wi-Fi.

Use a real AP or switch as the RADIUS client.

Steps:

1. Connect the AP management side so it can reach the AegisNAS VM.
2. Add the AP in `RADIUS Clients`.
3. Use the AP IP address and shared secret.
4. Configure the AP SSID for WPA2-Enterprise or WPA3-Enterprise.
5. Set RADIUS auth server to AegisNAS IP, port `1812`.
6. Set accounting server to AegisNAS IP, port `1813`.
7. Join the SSID from a real client.

Check:

```bash
journalctl -u freeradius -n 160 --no-pager
journalctl -u aegis-radius -n 160 --no-pager
sqlite3 /var/lib/aegisnas/data.db \
  "SELECT username, auth_method, role, vlan, bandwidth_profile, end_time FROM sessions ORDER BY start_time DESC LIMIT 10;"
```

## 24. AI Engine Test

Lite profile:

```text
AI Engine disabled is expected.
```

Branch profile:

```text
AI mode: lite
Provider: local
```

Enterprise full AI:

Set `/etc/default/aegisnas`:

```bash
sudo sed -i '/^AEGIS_AI_API_KEY=/d' /etc/default/aegisnas
sudo sh -c 'echo AEGIS_AI_API_KEY=replace-with-provider-key >> /etc/default/aegisnas'
sudo chmod 0640 /etc/default/aegisnas
```

Set config through UI or YAML:

```yaml
ailite:
  enabled: true
  mode: "full"
  provider: "openai-compatible"
  endpoint: "https://ai.example.net"
  model: "ops-model"
  api_key_env: "AEGIS_AI_API_KEY"
```

Restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart aegis-ai-lite
```

Run analysis:

```bash
TOKEN="$(sudo awk -F= '/^AEGIS_ADMIN_BOOTSTRAP_TOKEN=/{print $2}' /etc/default/aegisnas)"
curl -fsS -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:8083/api/v1/ai-recommendations/run
```

Admin UI:

```text
AI Insights -> Run Analysis
```

Expected full AI recommendations use:

```text
source: ai_full
```

## 25. Backup And Restore Test

Admin UI:

```text
Backups -> Download Config
```

Save the JSON.

Then test restore:

```text
Backups -> Upload And Restore
```

CLI full backup pattern:

```bash
sudo tar -czf /var/tmp/aegisnas-backup-$(date +%Y%m%dT%H%M%S).tgz \
  /etc/aegisnas \
  /etc/default/aegisnas \
  /var/lib/aegisnas
```

## 26. Config Revision And Rollback Test

Admin UI:

1. change a harmless setting, such as portal branding
2. save settings
3. open `Config Revisions`
4. confirm a revision exists
5. rollback to the previous revision
6. confirm the setting returns

After rollback:

```bash
sudo systemctl restart aegis-admin-api aegis-portal aegis-gateway aegis-session
```

## 27. Stop And Start All Services

Stop:

```bash
sudo systemctl stop \
  aegis-gateway \
  aegis-radius \
  aegis-portal \
  aegis-session \
  aegis-policy \
  aegis-admin-api \
  aegis-ai-lite \
  aegis-telemetry \
  freeradius \
  dnsmasq
```

Optional firewall stop:

```bash
sudo systemctl stop nftables
```

Start:

```bash
sudo systemctl daemon-reload
sudo systemctl start nftables
sudo systemctl start dnsmasq freeradius
sudo systemctl start \
  aegis-gateway \
  aegis-radius \
  aegis-portal \
  aegis-session \
  aegis-policy \
  aegis-admin-api \
  aegis-ai-lite \
  aegis-telemetry
```

Verify:

```bash
systemctl --no-pager --full status aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api dnsmasq freeradius nftables
```

## 28. Reboot Recovery

If you used `--skip-netplan`, the LAN IP may need to be applied again after reboot:

```bash
sudo ip link set ens37 up
sudo ip addr replace 192.168.50.1/24 dev ens37
sudo systemctl restart dnsmasq nftables
sudo systemctl restart aegis-gateway aegis-portal aegis-session aegis-policy aegis-admin-api aegis-radius
```

Or rerun bootstrap:

```bash
cd ~/aegisnas-pi4
git pull --ff-only
bash scripts/ubuntu-vm-bootstrap.sh \
  --wan ens33 \
  --lan ens37 \
  --profile lite \
  --skip-packages \
  --skip-netplan \
  --force-config
```

## 29. Update From GitHub

```bash
cd ~/aegisnas-pi4
git status --short
git pull --ff-only
bash scripts/ubuntu-vm-bootstrap.sh \
  --wan ens33 \
  --lan ens37 \
  --profile lite \
  --skip-packages \
  --skip-netplan \
  --force-config
```

If pull is blocked by local script changes:

```bash
git restore scripts/ubuntu-vm-bootstrap.sh
git pull --ff-only
```

## 30. Common Failures And Fixes

### Permission denied running bootstrap

Use:

```bash
bash scripts/ubuntu-vm-bootstrap.sh ...
```

Or:

```bash
chmod +x scripts/ubuntu-vm-bootstrap.sh
./scripts/ubuntu-vm-bootstrap.sh ...
```

### Port 53 already in use

Check:

```bash
sudo ss -ltnup '( sport = :53 )'
```

The current config should bind `dnsmasq` to `192.168.50.1:53` and allow `systemd-resolved` to keep loopback DNS.

Restart:

```bash
sudo systemctl restart dnsmasq
```

### FreeRADIUS certificate validation failure

Regenerate and apply config:

```bash
sudo /opt/aegisnas/bin/aegis-radius apply-config --config /etc/aegisnas/config.yaml
sudo systemctl restart freeradius aegis-radius
```

Check:

```bash
journalctl -u freeradius -n 120 --no-pager
```

### Text file busy during install

Stop services first:

```bash
sudo systemctl stop aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api aegis-ai-lite aegis-telemetry
```

Then rerun bootstrap.

### Database is locked during first startup

Wait a few seconds, then restart the affected service:

```bash
sudo systemctl restart aegis-portal aegis-policy aegis-session aegis-admin-api
```

### Admin UI cannot be reached from Windows host

Try the WAN IP:

```bash
hostname -I
```

Then open:

```text
http://<wan-ip>:8083
```

If using host-only LAN IP from Windows, make sure the Windows VMware host-only adapter can route to `192.168.50.0/24`.

### Portal cannot be reached from Windows host on 192.168.50.1

First confirm the AegisNAS LAN NIC has carrier and the portal is listening:

```bash
ip -br link show ens37
ip -br addr show ens37
ss -ltnp | grep 8081
curl -i "http://192.168.50.1:8081/?client_mac=manual-browser-01"
```

Expected:

```text
ens37 UP ... LOWER_UP
ens37 UP 192.168.50.1/24
aegis-portal listening on *:8081
```

If `ens37` shows `NO-CARRIER`, connect VMware `Network Adapter 2`:

```text
VMware Player -> VM Settings -> Network Adapter 2
Connected: checked while VM is running
Connect at power on: checked
Network connection: Host-only
```

Then verify Windows is on the same VMware host-only network:

```powershell
ipconfig
ping 192.168.50.1
arp -a | findstr 192.168.50.1
Test-NetConnection 192.168.50.1 -Port 8081
```

Expected Windows adapter:

```text
VMware Network Adapter VMnet1
IPv4 Address: 192.168.50.2
Subnet Mask: 255.255.255.0
```

If ARP resolves but TCP 8081 fails, check that nftables allows the portal port:

```bash
nft list chain inet aegis input | grep 8081
```

Current builds should include a LAN input rule for portal traffic. For a temporary live lab fix on an older build:

```bash
nft insert rule inet aegis input iif "ens37" tcp dport 8081 accept
```

Then make it durable by pulling the latest code and rerunning bootstrap or restarting `aegis-gateway` after the updated ruleset is installed.

### Client does not get 192.168.50.x

Check dnsmasq:

```bash
systemctl --no-pager --full status dnsmasq
sudo journalctl -u dnsmasq -n 80 --no-pager
```

Then either disable VMware DHCP on that host-only network or set the client IP manually.

### Client logs in but internet does not work

Check from AegisNAS:

```bash
curl -I https://example.com
sysctl net.ipv4.ip_forward
sudo nft list ruleset
ip route
```

Expected:

```text
net.ipv4.ip_forward = 1
WAN default route exists
nftables NAT and forward rules exist
```

Restart gateway and nftables:

```bash
sudo systemctl restart nftables aegis-gateway aegis-session
```

Capture logs:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario internet-after-login-failure
```

## 31. Final Acceptance Checklist

Mark each item:

```text
[ ] AegisNAS VM has WAN and LAN NICs
[ ] WAN internet works from AegisNAS VM
[ ] LAN interface is 192.168.50.1/24
[ ] Bootstrap completed
[ ] Admin token retrieved with sudo
[ ] Admin UI login works
[ ] Dashboard core services are ok
[ ] guest1 / guest123 user exists
[ ] Manual same-VM portal login works
[ ] Client VM is on AegisNAS LAN side
[ ] Client receives or uses 192.168.50.x
[ ] Client opens portal
[ ] guest1 login succeeds
[ ] Client has internet after login
[ ] Session appears in admin UI
[ ] Logout or terminate ends the session
[ ] Voucher login works
[ ] RADIUS auth test works
[ ] Accounting Start works
[ ] Accounting Interim works
[ ] Accounting Stop works
[ ] Disconnect test works
[ ] Vendor dictionary is installed
[ ] Backup download works
[ ] Rollback test works
[ ] Log bundles are captured for success and failure cases
```

Keep the log bundle path with your test notes:

```text
/var/tmp/aegisnas-login-debug/<timestamp>-<scenario>
```
