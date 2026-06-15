# Wireless Access And UI Guide

This guide is the day-two operator playbook for turning AegisNAS into a full Network Access Server appliance with:

- captive portal guest access
- WPA2-Enterprise with EAP
- WPA3 personal and enterprise Wi-Fi options
- LDAP-backed identity
- upstream RADIUS / AAA integration
- manually managed SSIDs and appliance settings from the admin UI

It assumes the base appliance deployment is already done. For OS install and service layout, use [ubuntu-appliance-deployment.md](ubuntu-appliance-deployment.md) first.

## What The Product Can Do

With the current implementation, the appliance can act as the control point for:

- open SSIDs
- captive portal SSIDs
- WPA2-Personal SSIDs
- WPA2-Enterprise SSIDs
- WPA3-Personal SSIDs
- WPA3-Enterprise SSIDs
- local user and voucher fallback
- LDAP-backed portal auth
- brokered RADIUS auth to upstream AAA
- upstream accounting
- CoA and disconnect handling
- immediate gateway quarantine when a live session is reclassified into quarantine role, Filter-Id, or VLAN 99
- live gateway bandwidth shaping for active sessions with named bandwidth profiles
- automatic reauthentication when a live VLAN reassignment is requested through CoA

The admin UI now exposes the main manual control surfaces:

- `Dashboard`
- `Access Settings`
- `Admin Access`
- `RADIUS Clients`
- `Portal Profiles`
- `Identity Sources`
- `Roles`
- `Bandwidth Profiles`
- `VLANs`
- `Devices`
- `Vendor Compatibility`
- `Guest Requests`
- `Sessions`
- `Alerts`
- `Revisions`
- `Backups`
- `AI Insights`

When guest workflows, onboarding, or delegated-admin features are enabled, those pages become part of the normal wireless day-two workflow rather than optional extras.

## Important Platform Notes

Before you build around Wi-Fi, keep these two realities in view:

1. For real SSID broadcasting on Ubuntu, you need `hostapd` and a supported Wi-Fi adapter.
2. Inside a VM, Wi-Fi usually needs PCI or USB passthrough. A plain virtual NIC is not a real radio.

That means:

- for a physical appliance, run `hostapd` locally on the box
- for a VM, use AegisNAS as the RADIUS, portal, and policy appliance, and let an external AP broadcast the SSIDs

## Packages And Services

On Ubuntu, install the Wi-Fi runtime package in addition to the core appliance packages:

```bash
sudo apt-get update
sudo apt-get install -y hostapd
```

Enable it, but do not worry if it cannot start before the config exists:

```bash
sudo systemctl enable hostapd
```

## UI-First Setup Flow

### 1. Log In To The Admin UI

Open:

```text
http://<appliance-lan-ip>:8083
```

Use the bootstrap admin token created during seeding.

### 2. Create Your Reusable Policy Objects

Before editing SSIDs, create the reusable objects the Wi-Fi layer will reference.

Recommended order:

1. `Roles`
2. `Bandwidth Profiles`
3. `Portal Profiles`
4. `Identity Sources`
5. `VLANs`
6. `RADIUS Clients`

This keeps the SSID editor cleaner because you can pick known names instead of inventing them on the fly.

### 3. Add RADIUS Clients

Go to `RADIUS Clients` and add every device that will send RADIUS traffic to the appliance.

Typical entries:

- AP controllers
- standalone APs
- switches
- test supplicants or lab bridges

For each client, fill:

- `Short Name`
- `IP Address`
- `Shared Secret`
- `NAS Type / Vendor Profile`
- `Description`
- `Enabled`

Use `other` for standards-based or unknown clients. Use a known profile such as `aruba`, `cisco`, `mikrotik`, `ruckus`, `fortinet`, `ubnt`, `cambium`, `extreme`, `juniper`, `huawei`, `h3c`, `paloalto`, or `tplink` when that AP, controller, switch, firewall, or VPN gateway should receive vendor-compatible reply attributes. `unifi`, `routeros`, `canopy`, `junos`, and `omada` are accepted aliases.

Apply the pending changes after staging them.

Use `Vendor Compatibility` to confirm each client profile, preview reply attributes, check the effective reply pack, and review fallback warnings before testing a new AP or controller family.

### 4. Configure Portal And Directory Settings

Go to `Access Settings`, then work through the `Captive Portal And Directory` section.

For captive portal guest access:

- turn `Portal Enabled` on
- keep `Local Fallback` on unless you intentionally want hard dependency on external systems
- set `Branding`, `Success URL`, and `Logout URL`

For LDAP:

- turn `LDAP Enabled` on
- set `LDAP URL`
- set `Base DN`
- set `Bind DN`
- set `Bind Password`
- set `User Filter`
- set `Group Filter`

If you want portal logins to go through the local FreeRADIUS broker and then upstream AAA:

- turn `Portal Uses RADIUS Broker` on

### 5. Configure Local FreeRADIUS And EAP

Still on `Access Settings`, use the `FreeRADIUS And EAP` section.

Set:

- `NAS Identifier`
- `Shared Secret`
- `Auth Port`
- `Acct Port`
- `Max Sessions`
- `Request Timeout`
- `Interim Update`
- `Cert Directory`

Then choose the EAP defaults:

- `Default EAP Type`
- `PEAP Inner`
- `TTLS Inner`
- `TLS Min`
- `TLS Max`

If your upstream platform or controller will send CoA or disconnect messages:

- enable `Dynamic Authorization`
- keep or change the `Dynamic Authorization Port`

### 6. Configure Upstream AAA

Use the `Upstream AAA Servers` section when AegisNAS should broker authentication to another RADIUS platform.

Turn `Upstream AAA Enabled` on, then set:

- `Realm`
- `Pool Strategy`
- `Status Check`
- `Response Window`
- `Zombie Period`
- `Revive Interval`
- `Check Interval`
- `Strip Realm`

Then add one or more upstream servers with:

- `Name`
- `Address`
- `Auth Port`
- `Acct Port`
- `Secret`

Recommended layout:

- server 1 = primary
- server 2 = secondary

### 7. Configure The Wireless Radio

In the `Wireless Radio And SSIDs` section, set the physical radio details:

- `Wireless Enabled`
- `Country Code`
- `Radio Interface`
- `Driver`
- `HW Mode`
- `Channel`
- `Beacon Interval`
- `hostapd Path`
- `WMM Enabled`
- `HT Enabled`
- `Control Socket`

Typical physical appliance values:

- interface: `wlan0`
- driver: `nl80211`
- hostapd path: `/etc/hostapd/hostapd.conf`

### 8. Add SSIDs

Each SSID can have its own auth behavior and policy references.

For each SSID, fill:

- `SSID Name`
- `Auth Mode`
- `Passphrase` when using WPA2-Personal
- `Bridge`
- `VLAN`
- `Portal Profile`
- `Identity Source`
- `Bandwidth Profile`
- `Max Clients`
- `Hidden`
- `Client Isolation`
- `Dynamic VLAN`

Current SSID auth modes supported by the UI and config generator:

- `Captive Portal`
- `Open`
- `WPA2 Personal`
- `WPA2 Enterprise`
- `WPA3 Personal`
- `WPA3 Enterprise`

Suggested product pattern:

- `Guest`: captive portal
- `Staff`: WPA3-Enterprise
- `IoT`: WPA2-Personal
- `Lab`: open or captive portal

### 9. Save Settings

Click `Save Settings`.

This writes the appliance YAML config and validates it first. If the UI accepts the save, the backend config is structurally valid.

### 10. Review The Generated hostapd Preview

Still on the same page, inspect the `hostapd Preview`.

This is useful for checking:

- SSID names
- enterprise auth blocks
- bridge references
- radio interface and channel
- whether the generated file reflects your intended auth mode

### 11. Write The hostapd Config

Click `Write hostapd Config` if you only want to stage the generated file on disk.

This writes the generated config to the configured `hostapd Path`.

If you want the UI to publish the radio change immediately, click `Write And Restart Wi-Fi`.

That writes the config and restarts `hostapd` on the appliance in one step.

You can still restart it manually:

```bash
sudo systemctl restart hostapd
sudo systemctl status hostapd --no-pager
```

If you are using an external AP instead of a local radio, skip this step and configure the AP to use AegisNAS as its RADIUS server.

### 12. Apply FreeRADIUS From The UI

When you change:

- shared secrets
- EAP defaults
- upstream AAA servers
- local RADIUS clients

use the `Apply RADIUS Config` button on `Access Settings`.

That regenerates the appliance FreeRADIUS files, validates them, and restarts the `freeradius` service on the appliance.

## Example Deployment Patterns

### Guest Captive Portal SSID

Use:

- auth mode: `Captive Portal`
- portal profile: guest branding profile
- identity source: local or LDAP-backed portal flow
- bandwidth profile: guest-limited
- optional VLAN: guest VLAN

Expected user experience:

1. client joins SSID
2. client receives DHCP and DNS
3. client is redirected to the captive portal
4. user authenticates or enters a voucher
5. session becomes active in `Sessions`

### Corporate WPA2-Enterprise SSID

Use:

- auth mode: `WPA2 Enterprise`
- dynamic VLAN if your upstream AAA returns VLAN attributes
- identity source: LDAP or upstream RADIUS policy source
- bandwidth profile: corporate profile

Expected user experience:

1. client joins SSID
2. supplicant performs PEAP, TTLS, or TLS
3. AegisNAS brokers auth locally or to upstream AAA
4. accounting and session tracking become visible on the appliance

### High-Security WPA3 SSID

Use:

- auth mode: `WPA3 Personal` for smaller trusted groups, or `WPA3 Enterprise` for managed devices
- identity source: LDAP or upstream RADIUS policy source for enterprise mode
- bandwidth profile: staff or admin profile

Expected user experience:

1. client joins SSID with WPA3-capable supplicant support
2. hostapd enforces PMF-required configuration
3. AegisNAS brokers enterprise auth locally or upstream when needed
4. sessions and policy remain visible in the same admin workflow

### VM Appliance With External AP

Use this when the appliance runs in VMware, Hyper-V, or KVM and the radio is not local.

Pattern:

1. keep `Wireless Enabled` off in AegisNAS if the VM is not hosting a real radio
2. still configure `RADIUS Clients`
3. point the external AP to AegisNAS for RADIUS
4. use AegisNAS for portal, session, policy, accounting, and AAA brokering

## Exact Deployment Checklists

### Guest Captive Portal Deployment

Use this checklist when you want a guest SSID that lands users on the AegisNAS captive portal and opens internet only after login.

Decide the radio model first:

- physical appliance with local Wi-Fi radio:
  - `Wireless Enabled = on`
  - SSID is created in AegisNAS and published through `hostapd`
- VM or non-radio appliance with external AP:
  - `Wireless Enabled = off`
  - create an open guest SSID on the AP
  - make the guest SSID network use AegisNAS as DHCP, DNS, and default gateway

Checklist:

- [ ] Ubuntu appliance deployment is complete and the core services are healthy
- [ ] The guest-side network reaches AegisNAS on the LAN side
- [ ] `Portal Enabled` is on in `Access Settings`
- [ ] `Local Fallback` is on unless you intentionally require LDAP or brokered RADIUS for portal logins
- [ ] At least one guest login path exists:
  - local user
  - voucher
  - LDAP-backed portal auth
  - brokered portal auth through the local RADIUS broker
- [ ] A reusable guest `Role` exists, such as `guest-basic`
- [ ] A guest `Bandwidth Profile` exists if you want shaped access
- [ ] A guest `Portal Profile` exists with the intended branding and success or logout URLs
- [ ] The LAN DHCP scope hands clients an IP, gateway, and DNS that all point to AegisNAS
- [ ] The firewall rules allow LAN access to DNS, DHCP, admin, health, and portal `8081`
- [ ] For a physical appliance, the Wi-Fi radio is supported by Ubuntu and `hostapd`
- [ ] For a physical appliance, `Wireless Enabled` is on and the radio settings are correct:
  - interface such as `wlan0`
  - driver `nl80211`
  - country code
  - channel
  - `hostapd Path`
- [ ] For a physical appliance, a guest SSID exists with:
  - `Auth Mode = Captive Portal`
  - guest `Portal Profile`
  - guest `Bandwidth Profile`
  - optional `Bridge`
  - optional guest VLAN
  - optional `Client Isolation`
- [ ] For a physical appliance, `hostapd Preview` looks correct
- [ ] For a physical appliance, `Write hostapd Config` or `Write And Restart Wi-Fi` has been run
- [ ] For an external AP, the AP guest SSID is open and does not use the AP vendor's own captive portal
- [ ] For an external AP, guest clients are routed through AegisNAS after association
- [ ] A test client joins the guest SSID and receives DHCP from AegisNAS
- [ ] Before login, opening `http://neverssl.com` or another plain HTTP site reaches the AegisNAS portal
- [ ] The portal page also opens directly at `http://<appliance-lan-ip>:8081`
- [ ] `guest1 / guest123` or a valid voucher or LDAP credential logs in successfully
- [ ] After login, the client can browse the internet through AegisNAS
- [ ] A live session appears in `Sessions`
- [ ] Logging out from the portal or terminating the session removes access and the client must authenticate again
- [ ] A debug bundle is captured for future R&D:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario guest-captive-portal
```

### Enterprise WPA2/WPA3 With External AAA

Use this checklist when APs or controllers should enforce WPA2-Enterprise or WPA3-Enterprise while AegisNAS brokers RADIUS to upstream AAA systems and keeps local policy, accounting, and session control.

This is usually the right model for:

- external APs and controllers
- VM-based AegisNAS deployments
- enterprise WLANs with Microsoft NPS, Cisco ISE, Aruba ClearPass, FreeRADIUS, or similar upstream AAA

Checklist:

- [ ] The upstream AAA platform is reachable from AegisNAS
- [ ] The upstream AAA platform has a RADIUS client entry for the AegisNAS appliance IP
- [ ] The upstream AAA shared secret matches the AegisNAS upstream server definition
- [ ] The upstream AAA server allows auth on UDP `1812`
- [ ] The upstream AAA server allows accounting on UDP `1813`
- [ ] The upstream AAA server allows dynamic authorization on UDP `3799` if CoA or disconnect is required
- [ ] The expected username format is known:
  - plain username
  - `user@realm`
  - `DOMAIN\user`
- [ ] The expected upstream reply attributes are known:
  - VLAN
  - `Filter-Id`
  - bandwidth mapping hints
  - session timeout
  - idle timeout
  - AegisNAS vendor-specific attributes if product-mode mapping is used
- [ ] The `RADIUS Clients` list in AegisNAS includes every AP, controller, or switch that will send RADIUS traffic to AegisNAS
- [ ] Each `RADIUS Clients` entry has the intended `NAS Type / Vendor Profile` so generated FreeRADIUS `clients.conf` and reply attributes match the device vendor
- [ ] `Access Settings -> FreeRADIUS And EAP` is configured with:
  - `NAS Identifier`
  - local shared secret
  - auth port
  - accounting port
  - request timeout
  - interim update interval
  - EAP defaults
  - dynamic authorization settings if needed
- [ ] `Access Settings -> Upstream AAA Servers` has:
  - `Upstream AAA Enabled = on`
  - realm
  - pool strategy
  - status-check mode
  - one or more upstream servers with address, ports, and secret
- [ ] Identity-source mapping is configured if upstream `Filter-Id`, VLAN, or vendor attributes should become local role, VLAN, or bandwidth policy
- [ ] The intended enterprise `Role`, `Bandwidth Profile`, and optional VLAN mappings exist in AegisNAS
- [ ] `Apply RADIUS Config` has been run successfully from `Access Settings`
- [ ] `freeradius` and `aegis-radius` are healthy after apply
- [ ] For a physical appliance using a local radio, a secure SSID exists with:
  - `Auth Mode = WPA2 Enterprise` or `WPA3 Enterprise`
  - `Identity Source = radius-upstream` or the intended enterprise identity source
  - `Dynamic VLAN = on` when upstream VLAN assignment is expected
- [ ] For a physical appliance using a local radio, `hostapd Preview` reflects the intended enterprise SSID
- [ ] For a physical appliance using a local radio, `Write hostapd Config` or `Write And Restart Wi-Fi` has been run
- [ ] For an external AP or controller, the SSID is configured on the AP side as WPA2-Enterprise or WPA3-Enterprise
- [ ] For an external AP or controller, the AP points RADIUS auth and accounting to AegisNAS, not directly to the upstream AAA server
- [ ] For an external AP or controller, the AP shared secret matches the `RADIUS Clients` entry on AegisNAS
- [ ] A test supplicant joins the enterprise SSID and completes EAP successfully
- [ ] A session appears in `Sessions` after successful auth
- [ ] Accounting `Start` reaches AegisNAS and the upstream AAA path
- [ ] Interim accounting reaches the upstream AAA server when the session stays up
- [ ] `Stop` or disconnect accounting is visible when the session ends
- [ ] CoA or disconnect works when the upstream AAA platform sends a policy change or termination request
- [ ] A debug bundle is captured for future R&D:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario enterprise-external-aaa
```

## Manual Validation Checklist

After configuration, check these paths:

1. `Access Settings` page reloads without errors
2. `hostapd Preview` matches the saved SSIDs
3. dashboard service cards stay healthy after apply
4. dashboard upstream AAA cards reflect the real primary and secondary server state
5. dashboard runtime shaping card reflects the downstream interface and shaped session count
6. `RADIUS Clients` list contains the real AP or switch addresses
7. `Sessions` shows live sessions during testing
8. `Alerts` stays clear of repeated auth failures
9. `Config Revisions` captures your changes
10. `Backups` exports cleanly

CLI checks:

```bash
sudo /opt/aegisnas/bin/aegis-admin validate-config --config /etc/aegisnas/config.yaml
sudo /opt/aegisnas/bin/aegis-radius apply-config --config /etc/aegisnas/config.yaml
sudo systemctl restart hostapd
sudo journalctl -u freeradius -u hostapd -u aegis-portal -u aegis-session -n 100 --no-pager
```

## Rollback

If an SSID or auth policy change goes sideways:

1. use `Config Revisions` to identify the last good revision
2. use the rollback action
3. write the hostapd config again if the radio config changed
4. restart `hostapd`
5. re-apply FreeRADIUS config if AAA settings changed

## Future Maintainer Notes

The current UI intentionally centers around `Access Settings` so operators can make most changes from one screen.

When extending the product next, the most likely follow-up improvements are:

1. client portal theming from the same admin console
2. appliance service status and restart controls for the full stack from the same admin console
3. richer controller-aware AP synchronization workflows for enterprise Wi-Fi
4. external AP synchronization workflows for controller-managed Wi-Fi
