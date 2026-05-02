# Login And Captive Portal Test Runbook

This runbook is the focused acceptance guide for every major AegisNAS login path, with extra attention on the full captive portal journey where a client gains internet access only after authentication.

Use this guide when you want:

- a repeatable captive portal test for local users, vouchers, LDAP, and brokered AAA
- a clean checklist for admin UI, portal, and 802.1X login validation
- a standard way to capture separate logs for future debugging and R&D

Use this guide together with:

- [Ubuntu VM Deployment And Full Flow Test Runbook](ubuntu-vm-runbook.md)
- [Wireless Access And UI Guide](wireless-access-ui-guide.md)
- [External AAA Product Mode](external-aaa-product-mode.md)

## What This Guide Covers

This guide covers:

1. admin UI bootstrap token login
2. captive portal login with a local user
3. captive portal self-registration and sponsor approval
4. device onboarding and certificate retrieval
5. captive portal login with a voucher
6. captive portal login backed by LDAP
7. captive portal login through the local FreeRADIUS broker and upstream AAA
8. 802.1X or EAP login through an external AP
9. logout, re-login, and negative-path checks
10. separate log bundle capture for future debugging and R&D

## Recommended Lab Topology

For any test that must prove "internet works after login", place the client behind the AegisNAS LAN side.

```text
Client VM or device -> LAN side -> AegisNAS VM -> WAN side -> upstream internet
```

Typical VM lab:

- AegisNAS VM
  - `ens33` or equivalent: WAN or upstream side
  - `ens37` or equivalent: LAN or host-only side
- client VM
  - one NIC only
  - attached to the same host-only or isolated lab network as the AegisNAS LAN NIC

Important platform reality:

- opening the admin UI from your host browser proves management access
- it does not prove captive enforcement or internet-after-login
- for that, the client must use `192.168.50.1` as gateway and DNS on the LAN side

## Shared Preconditions

Before any login-path test:

1. confirm the appliance services are healthy
2. confirm the client can reach the LAN-side portal IP
3. capture a baseline log bundle

Recommended appliance health check:

```bash
systemctl --no-pager --full status aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api dnsmasq freeradius nftables
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8081/health
curl -fsS http://127.0.0.1:8082/health
curl -fsS http://127.0.0.1:8083/health
curl -fsS http://127.0.0.1:8085/health
curl -fsS http://127.0.0.1:8087/health
```

Recommended client-side LAN check:

- IP address is `192.168.50.x`
- gateway is `192.168.50.1`
- DNS is `192.168.50.1`
- `ping 192.168.50.1` works
- `http://192.168.50.1:8081` opens

## Log Capture Workflow

Use the helper script before, during, and after each test case:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario prelogin-baseline
sudo bash scripts/capture-login-debug-logs.sh --scenario portal-local-success
sudo bash scripts/capture-login-debug-logs.sh --scenario portal-local-failure
```

The script writes a timestamped bundle with separate files for:

- each systemd service log
- network state
- health endpoint output
- redacted config and environment snapshots

Recommended capture points:

1. before the test starts
2. immediately after a successful login
3. immediately after a failure
4. after logout or forced session termination

## Test Matrix

| Scenario | Client position | Identity source | Internet expected after login | Primary evidence |
| --- | --- | --- | --- | --- |
| Admin UI bootstrap login | management browser | bootstrap token | not applicable | dashboard loads |
| Portal local user | LAN-side client | `local_users` | yes | session shows portal-local auth |
| Portal self-registration and sponsor approval | LAN-side client plus sponsor path | guest workflow | yes | `Guest Requests` shows approval path and session starts after approval |
| Onboarding and certificate retrieval | LAN-side client plus admin UI | onboarding runtime | usually yes after registration | `Devices` shows the device and certificate bundle |
| Portal voucher | LAN-side client | `vouchers` | yes | voucher usage increments |
| Portal LDAP | LAN-side client | LDAP | yes | session shows LDAP-backed auth |
| Portal brokered AAA | LAN-side client | FreeRADIUS broker and upstream AAA | yes | `aegis-radius` and `freeradius` logs show auth path |
| EAP or 802.1X | AP-side client | FreeRADIUS local or upstream | yes | client joins SSID and receives role or policy |
| Logout and re-login | LAN-side client | any of the above | access removed after logout | session ends and client must log in again |

## 1. Admin UI Bootstrap Token Login

Purpose:

- confirm the management plane is reachable
- verify the bootstrap token still works

Steps:

1. retrieve the bootstrap token:

```bash
sudo grep AEGIS_ADMIN_BOOTSTRAP_TOKEN /etc/default/aegisnas | cut -d= -f2-
```

2. open:

```text
http://192.168.159.132:8083
```

3. sign in with the token
4. load `Dashboard`, `Access Settings`, `Users`, `Vouchers`, `Roles`, `Sessions`

Pass condition:

- login succeeds
- no redirect loop appears
- pages load without returning to the login screen

## 2. Captive Portal Local User Login With Internet After Login

Purpose:

- validate the simplest end-to-end guest path
- prove internet works only after the user is authenticated

Setup:

1. in the admin UI, open `Users`
2. create a local portal test user, for example:
   - username: `guest1`
   - password: `guest123`
   - role: `guest-basic`
3. keep the record until testing is complete

Steps:

1. capture a baseline bundle:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario portal-local-prelogin
```

2. from the LAN-side client, browse to:

```text
http://192.168.50.1:8081
```

3. log in with the local test user
4. after login, test internet from the same client:

```bash
curl http://neverssl.com
curl https://example.com
nslookup example.com 192.168.50.1
```

5. in the admin UI, open `Sessions`
6. confirm a new session appears for the client
7. capture a success bundle:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario portal-local-postlogin
```

8. log out from the portal success page or terminate the session from `Sessions`
9. retry `http://neverssl.com` from the client

Pass condition:

- login succeeds
- the client reaches internet after login
- a session appears in `Sessions`
- the session auth method is the local portal path
- logout ends access and the client must authenticate again

If you want a truer redirect test:

- browse to any plain HTTP site before login
- confirm the client lands on the portal page

## 2A. Guest Self-Registration And Sponsor Approval

Purpose:

- validate the end-to-end guest-request path
- prove approval can happen through the portal workflow or sponsor link

Setup:

1. in `Access Settings`, enable:
   - `portal.guest_workflows.self_registration_enabled`
2. if sponsor approval is in scope, also enable:
   - `portal.guest_workflows.sponsor_approval_enabled`
3. configure email or SMS delivery if approval links should be delivered externally

Steps:

1. capture a baseline bundle
2. from the LAN-side client, open the portal
3. choose `Request guest access`
4. submit the request
5. approve it from `Guest Requests` or from the sponsor approval link
6. confirm the original client completes the portal flow
7. test internet from the client after approval
8. capture a success bundle

Pass condition:

- request submission succeeds
- approval or rejection state is visible in `Guest Requests`
- approval creates a usable guest credential path
- internet works after approval

## 2B. Onboarding And Certificate Retrieval

Purpose:

- validate the device inventory and certificate workflow
- confirm internal or external CA enrollment behaves as configured

Setup:

1. in `Access Settings`, enable the onboarding features in scope:
   - `device_inventory_enabled`
   - `portal_enabled`
   - `certificate_enrollment_enabled`
2. choose:
   - `ca_mode: internal`, or
   - `ca_mode: external`
3. if using external CA mode, configure:
   - `ca_enrollment_url`
   - `ca_enrollment_token_env` as needed

Steps:

1. capture a baseline bundle
2. from the LAN-side client, run the onboarding flow
3. open `Devices` in the admin UI
4. confirm the device appears
5. retrieve the certificate bundle
6. if external CA is enabled, confirm the enrollment completed successfully
7. capture a success bundle

Pass condition:

- the device is inventoried
- certificate retrieval works
- external CA mode works when configured

## 3. Captive Portal Voucher Login

Purpose:

- confirm guest access works without a named local account

Setup:

1. open `Vouchers`
2. create a voucher with:
   - code
   - role such as `guest-basic`
   - duration
   - usage limit
   - expiry

Steps:

1. capture a baseline bundle:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario portal-voucher-prelogin
```

2. from the LAN-side client, open:

```text
http://192.168.50.1:8081
```

3. choose the voucher path
4. submit the voucher code
5. test internet from the client after login
6. confirm a session appears in `Sessions`
7. confirm `used_count` increases in `Vouchers`
8. capture a success bundle

Pass condition:

- voucher login succeeds
- internet works after login
- the session auth method is `voucher`
- voucher usage updates correctly

## 4. Captive Portal LDAP Login

Purpose:

- prove the portal can authenticate against LDAP while still enforcing downstream internet access through AegisNAS

Setup:

1. open `Access Settings`
2. configure the LDAP section:
   - `LDAP Enabled`
   - `LDAP URL`
   - `Base DN`
   - `Bind DN`
   - `Bind Password`
   - `User Filter`
   - `Group Filter`
3. save and apply changes
4. keep `Local Fallback` on unless you want a hard LDAP dependency

Steps:

1. capture a baseline bundle
2. from the LAN-side client, open the portal
3. log in with a valid LDAP username and password
4. test internet after login
5. verify the client session appears in `Sessions`
6. capture a success bundle

Pass condition:

- LDAP login succeeds
- internet works after login
- the session reflects LDAP-backed identity

## 5. Captive Portal Brokered AAA Login

Purpose:

- validate the portal path when AegisNAS uses the local broker and then forwards to upstream AAA

Setup:

1. open `Access Settings`
2. in `Captive Portal And Directory`, enable:
   - `Portal Uses RADIUS Broker`
3. in `Upstream AAA Servers`, enable upstream AAA and configure:
   - realm
   - pool strategy
   - status check
   - response timers
   - one or more upstream servers
4. save and apply
5. use a user that exists only on the upstream system

Steps:

1. capture a baseline bundle
2. open the portal from a LAN-side client
3. log in with the upstream AAA user
4. test internet after login
5. verify the session appears in `Sessions`
6. inspect `aegis-radius` and `freeradius` logs in the bundle
7. capture a success bundle

Pass condition:

- brokered portal login succeeds
- internet works after login
- `aegis-radius` and `freeradius` remain healthy
- the logs show the request path through the local broker

## 6. 802.1X Or EAP Login Through An External AP

Purpose:

- validate enterprise Wi-Fi authentication that uses AegisNAS as the RADIUS, policy, and session system

Prerequisites:

- external AP or Wi-Fi hardware passthrough
- SSID configured for `wpa2-enterprise`, `wpa3-enterprise`, or equivalent
- AP points its RADIUS auth and accounting traffic at AegisNAS

Steps:

1. configure the SSID and RADIUS client entry in the admin UI
2. capture a baseline bundle
3. join the SSID from a wireless client with valid credentials
4. confirm the client receives an IP address on the expected VLAN or subnet
5. test internet access after successful join
6. confirm the session appears in `Sessions`
7. capture a success bundle

Pass condition:

- the client joins successfully
- internet works after join
- the expected role, VLAN, and policy are applied

## 7. Logout, Re-Login, And Session Termination

Purpose:

- prove session teardown works and access is removed immediately enough for real-world troubleshooting

Steps:

1. establish an active session through any login path above
2. capture a pre-logout bundle
3. log out from the portal, disconnect from the SSID, or terminate the session from `Sessions`
4. verify access drops:
   - browse to an HTTP site
   - confirm the client is redirected back to the portal or must reauthenticate
5. log in again
6. capture a post-logout or post-relogin bundle

Pass condition:

- the original session ends
- access is removed after logout or termination
- re-login creates a new session cleanly

## 8. Negative Tests

Run these for each login path you care about:

1. invalid password
2. expired voucher
3. exhausted voucher usage limit
4. LDAP unavailable with fallback enabled
5. LDAP unavailable with fallback disabled
6. upstream AAA unavailable with `portal.radius_auth: true`
7. session termination while the client is still browsing

Pass condition:

- the user receives the expected denial or fallback behavior
- stale access does not remain available
- a failure bundle is captured for later analysis

## Separate Log Files For Future Debugging And R&D

The helper script produces a bundle like:

```text
/var/tmp/aegisnas-login-debug/20260421T120000Z-portal-local-postlogin/
  summary/
  network/
  logs/
  state/
```

Recommended scenario names:

- `prelogin-baseline`
- `portal-local-prelogin`
- `portal-local-postlogin`
- `portal-local-failure`
- `portal-voucher-postlogin`
- `portal-ldap-postlogin`
- `portal-radius-postlogin`
- `eap-postjoin`
- `logout-postcheck`

Recommended evidence to keep with each bundle:

- client IP
- client MAC
- login type
- username or voucher code reference
- role expected
- VLAN expected
- whether internet worked
- whether logout removed access

## R&D Notes Template

Copy this into your test notes for each run:

```text
Scenario:
Date:
Appliance build or commit:
Client type:
Client MAC:
Client IP:
Gateway:
DNS:
Login path:
Identity used:
Expected role:
Expected VLAN:
Expected bandwidth:
Internet after login:
Logout removed access:
Observed issues:
Log bundle path:
```

## Quick Pass Summary

The login system is in good shape when:

- admin UI login works
- captive portal local login works
- voucher login works
- LDAP login works when enabled
- brokered AAA login works when enabled
- EAP works when an external AP or Wi-Fi radio is present
- sessions appear and disappear correctly
- internet is unavailable before login and available after login on the LAN-side client
