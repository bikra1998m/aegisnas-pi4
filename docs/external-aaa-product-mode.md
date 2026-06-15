# External AAA Product Mode

This guide documents the product mode where AegisNAS acts as a Network Access Server appliance in front of one or more external AAA systems.

In this mode:

- APs, switches, or other NAS clients point to AegisNAS for RADIUS
- AegisNAS runs local FreeRADIUS as the edge broker
- local FreeRADIUS proxies authentication and accounting to upstream AAA servers
- portal logins can use that same broker path
- the session service owns timeout enforcement, interim accounting, CoA, and disconnect handling
- AegisNAS keeps its own admin UI, policy engine, session tracking, backups, and gateway behavior

This is the right mode when you want the product to sit at the edge while still interoperating with enterprise identity or policy systems such as:

- FreeRADIUS
- Microsoft NPS
- Cisco ISE
- Aruba ClearPass
- FortiAuthenticator
- any other standards-based RADIUS AAA platform

## What Changed In The Code

Files involved:

- [config.go](F:/random_project/Pookie/aegisnas-pi4/internal/config/config.go)
- [auth.go](F:/random_project/Pookie/aegisnas-pi4/internal/portal/auth/auth.go)
- [server.go](F:/random_project/Pookie/aegisnas-pi4/internal/portal/server/server.go)
- [statemachine.go](F:/random_project/Pookie/aegisnas-pi4/internal/portal/statemachine.go)
- [generator.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/generator.go)
- [client.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/client.go)
- [vendor.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/vendor.go)
- [accounting.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/accounting.go)
- [mapping.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/mapping.go)
- [manager.go](F:/random_project/Pookie/aegisnas-pi4/internal/sessions/manager.go)
- [dynamic_auth.go](F:/random_project/Pookie/aegisnas-pi4/internal/sessions/dynamic_auth.go)
- [config.example.yaml](F:/random_project/Pookie/aegisnas-pi4/configs/config.example.yaml)

The implementation now does these things end to end:

1. adds `radius.upstream`, `radius.dynamic_auth`, `radius.nas_identifier`, and accounting timing config
2. generates FreeRADIUS `proxy.conf` automatically and always registers localhost as a broker client with the configured shared secret
3. lets captive portal username/password logins authenticate through local FreeRADIUS when `portal.radius_auth: true`
4. preserves break-glass local admin auth and local voucher flows
5. maps upstream reply attributes into local role, VLAN, bandwidth, `Filter-Id`, timeout, AegisNAS vendor attributes, and session state
6. sends `Accounting-Start`, `Accounting-Interim-Update`, and `Accounting-Stop`
7. listens for `CoA-Request` and `Disconnect-Request`
8. exposes appliance, broker, and per-upstream AAA health through the admin API dashboard
9. applies immediate gateway quarantine when a live session is reclassified into quarantine role, `Filter-Id`, or VLAN `99`
10. terminates a live session immediately when a `CoA-Request` tightens session or idle timeout past the session's current age
11. rebuilds live gateway bandwidth shaping from active `bandwidth_profile` assignments and forces reauthentication when a `CoA-Request` changes VLAN

## Current Behavior

When `radius.upstream.enabled: true`:

- inbound RADIUS auth requests are proxied to the configured upstream pool
- inbound RADIUS accounting requests are proxied to the configured upstream pool
- captive portal web logins can use the same broker path through `portal.radius_auth: true`
- upstream server failover and load distribution are handled by FreeRADIUS
- portal sessions keep a stable `Acct-Session-Id`
- the session service sends interim accounting on the configured interval
- the session service listens on `radius.dynamic_auth.port` for dynamic authorization
- the dashboard probes each upstream AAA home server directly with `Status-Server` when that mode is enabled
- the gateway rebuilds Linux `tc` shaping for any active session with a named bandwidth profile
- upstream reply attributes are mapped into local session state:
  - VLAN assignment
  - role mapping
  - bandwidth profile mapping
  - `Filter-Id` preservation
  - session timeout
  - idle timeout
  - AegisNAS vendor-specific attributes when `radius.vendor.enabled: true`
- break-glass local admin auth remains available even when portal RADIUS auth is enabled
- voucher logins remain local so guest access still has an offline path

What this pass still does not change:

- storage NAS services such as Samba, NFS, RAID, ZFS, and share management are still separate workstreams
- `Filter-Id` is mapped into local role and bandwidth policy, but not yet into a separate firewall ACL language
- `CoA-Request` can now trigger immediate gateway quarantine enforcement, immediate timeout expiry, live bandwidth profile reshaping, and VLAN-change reauthentication, but device-specific ACL semantics remain future work

That means the product is now a strong Network Access Server / AAA edge appliance, but not yet a full storage NAS distribution by itself.

## Architecture

Recommended traffic flow:

```text
Clients -> AP / switch -> AegisNAS -> local FreeRADIUS proxy -> external AAA
```

Recommended service layout on the appliance:

- `aegis-gateway` for firewall, DHCP-side coordination, and network edge behavior
- `aegis-radius` for generated FreeRADIUS config and service validation
- `aegis-portal` for guest portal and voucher flows
- `aegis-session` for local session lifecycle, interim accounting, and dynamic authorization
- `aegis-admin-api` and the admin UI for manual operations

## Step-By-Step Deployment

### 1. Prepare The External AAA System

On the upstream AAA platform:

1. create a RADIUS client for the AegisNAS appliance IP
2. assign a shared secret
3. allow authentication on UDP `1812`
4. allow accounting on UDP `1813`
5. allow dynamic authorization on UDP `3799` if CoA or disconnect is required
6. decide whether the upstream server supports `Status-Server`
7. confirm expected identity format:
   - username only
   - `user@realm`
   - `DOMAIN\user`
8. confirm what reply attributes it will return:
   - VLAN attributes
   - `Filter-Id`
   - `Class`
   - session timeout
   - idle timeout
   - bandwidth or vendor attributes

### 2. Point Access Devices At AegisNAS

Your APs or switches should use AegisNAS as their RADIUS server, not the upstream AAA system directly.

This keeps the product in control of:

- visibility
- failover
- staged updates
- local session tracking
- fallback options

### 3. Configure Upstream AAA In AegisNAS

You can do this either by editing YAML directly or by using the `Access Settings` page in the admin UI.

Edit [config.example.yaml](F:/random_project/Pookie/aegisnas-pi4/configs/config.example.yaml) into your real appliance config and set:

```yaml
radius:
  secret: "replace-this-radius-secret"
  nas_identifier: "aegisnas-edge-01"
  request_timeout_seconds: 5
  interim_update_seconds: 300
  dynamic_auth:
    enabled: true
    port: 3799
  vendor:
    enabled: true
    name: "AegisNAS"
    id: 55555 # Lab placeholder from configs/aegisnas-vendor.dictionery. Replace before production use.
    compatibility_packs: ["standard", "mikrotik", "wispr"] # Global default for unprofiled NAS clients.
    attributes: [] # Optional local overrides or extensions. Built-ins come from the product dictionary.
  auth_port: 1812
  acct_port: 1813
  clients:
    - ip: 127.0.0.1
      secret: "replace-this-radius-secret"
      shortname: "localhost"
      nas_type: "other"
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
      - name: "secondary-aaa"
        address: "10.10.10.11"
        auth_port: 1812
        acct_port: 1813
        secret: "replace-this-upstream-secret-too"

portal:
  radius_auth: true
  local_fallback: true
```

Notes:

- `pool_strategy` can be `fail-over`, `load-balance`, `client-balance`, `client-port-balance`, or `keyed-balance`
- use `status_check: status-server` only when the upstream platform supports it
- use `status_check: none` when the upstream vendor does not answer `Status-Server`
- `strip_realm: false` preserves the original username format sent by the access device
- `radius.vendor.id` must be your own IANA Private Enterprise Number for production; keep `55555` only for lab testing
- `aegis-radius apply-config` writes `/etc/freeradius/3.0/aegisnas-vendor.dictionery` and includes it from the local FreeRADIUS `dictionary`

### 4. Configure AegisNAS Vendor Attributes

AegisNAS can behave like a vendor NAS by publishing its own FreeRADIUS product dictionary and parsing its own Vendor-Specific Attributes. The product dictionary is the source of truth for built-in attribute names, numbers, and types.

The portable product dictionary template is:

- [aegisnas-vendor.dictionery](F:/random_project/Pookie/aegisnas-pi4/configs/aegisnas-vendor.dictionery)

On an appliance, `aegis-radius apply-config` writes:

- `/etc/freeradius/3.0/dictionary`
- `/etc/freeradius/3.0/aegisnas-vendor.dictionery`

The generated `dictionary` file contains:

```text
$INCLUDE aegisnas-vendor.dictionery
```

To see the current built-in attributes, read the dictionary instead of copying the list into YAML:

```bash
sed -n '1,220p' configs/aegisnas-vendor.dictionery
```

To inspect the runtime catalog and semantic registry from an appliance:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-compatibility | jq '.summary, .semantics[] | select(.compatibility_state == "planned")'
```

To inspect deployed NAS profile coverage and fallback clients:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-compatibility | jq '.profile_summary, .client_profiles[] | {shortname, nas_type, effective_packs, warning}'
```

To inspect dictionary coverage across compatibility packs:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-compatibility | jq '.dictionary_coverage.rows[] | {pack_key, active, coverage_state, dictionary_matched_attribute_count, missing_dictionary_attribute_count}'
```

To preview the exact reply attributes for a profile before testing hardware:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"nas_type":"aruba","role":"guest","vlan":20,"download_kbps":50000,"upload_kbps":20000}' \
  http://127.0.0.1:8083/api/v1/system/vendor-reply-preview | jq '.nas_type, .effective_packs, .attributes, .warnings'
```

The catalog layer reads FreeRADIUS-style `VENDOR`, `BEGIN-VENDOR`, `ATTRIBUTE`, and `VALUE` directives. The semantic layer is the product contract above that catalog. The dictionary coverage matrix compares parsed dictionary attributes with the compatibility packs, then reports whether each pack is `standard-radius`, `dictionary-backed`, `partial-dictionary`, `dictionary-missing`, or `controller-api`. Vendor compatibility packs should map Cisco, Aruba, MikroTik, Ruckus, Fortinet, UniFi, Mist, Cambium, and site-specific VSAs into these AegisNAS semantic keys instead of hard-coding controller behavior directly in policy code.

The current reply renderer has a conservative default pack set:

```yaml
radius:
  vendor:
    compatibility_packs:
      - standard
      - mikrotik
      - wispr
```

To compare compatibility packs against real FreeRADIUS vendor dictionaries, configure one or more import paths:

```yaml
radius:
  vendor:
    dictionary_paths:
      - /etc/freeradius/3.0/dictionary
      - /usr/share/freeradius
```

If no paths are configured, the admin API tries the standard appliance paths when they exist. Directory imports scan files named `dictionary`, `dictionary.*`, `*.dictionary`, or `*.dictionery`; file imports also expand local `$INCLUDE` lines.

Available pack keys include:

- `standard`
- `aegisnas`
- `mikrotik`
- `wispr`
- `cisco`
- `aruba`
- `ruckus`
- `fortinet`
- `ubnt`
- `mist`

Only enable a vendor pack after the AP, switch, controller, or upstream policy system is prepared to consume those attributes. A FreeRADIUS dictionary lets AegisNAS name and render an attribute; it does not guarantee that a device will enforce that attribute.

The `radius.vendor.attributes` list is only for local overrides or extra site-specific VSAs.

Example upstream Access-Accept reply:

```text
AegisNAS-Role := "guest-premium"
AegisNAS-Bandwidth-Profile := "50m-down-20m-up"
AegisNAS-VLAN := 20
AegisNAS-Session-Timeout := 3600
AegisNAS-Idle-Timeout := 600
```

Example CoA policy update:

```text
Acct-Session-Id = "existing-session-id"
AegisNAS-Bandwidth-Profile = "10m-down-5m-up"
AegisNAS-Quarantine = 1
```

AegisNAS also adds its vendor role, bandwidth profile, VLAN, policy tag, and timeout context to locally generated `Accounting-Start`, `Accounting-Interim-Update`, and `Accounting-Stop` packets when those values are present on the session.

### 5. Enable Reply-Attribute Mapping

The seeded `identity_sources` table now includes a disabled `radius-upstream` mapping source with example JSON.

Enable it from the admin UI or SQL and then customize the JSON to your upstream policy vocabulary.

Example:

```json
{
  "filter_id_roles": {
    "admins": "admin",
    "employees": "corp-standard"
  },
  "filter_id_bandwidth_profiles": {
    "premium": "100m-down-50m-up"
  },
  "vlan_roles": {
    "30": "corp-standard",
    "40": "admin"
  }
}
```

### 6. Keep RADIUS Clients Registered On The Appliance

The upstream AAA section defines where AegisNAS proxies requests.

The `radius.clients` list still defines which devices are allowed to send RADIUS traffic to AegisNAS itself.

The admin UI now exposes this as a dedicated `RADIUS Clients` page so operators can add APs and switches without editing YAML by hand.

Set `nas_type` to the access-device profile that should receive vendor-compatible replies. AegisNAS writes the value into generated FreeRADIUS `clients.conf` as `nastype` and uses known profile names to choose reply attribute packs for that client.

Common values:

- `other` uses `radius.vendor.compatibility_packs`
- `aruba` sends standards-based attributes plus Aruba role/VLAN replies
- `cisco` sends standards-based attributes plus Cisco ACL replies when policy contains ACL values
- `mikrotik` sends standards-based attributes plus MikroTik rate-limit replies
- `ubnt` or `unifi` sends standards-based attributes plus UniFi/UBNT rate replies
- `ruckus` and `fortinet` select their matching compatibility packs

Unknown safe names are still written as `nastype` for FreeRADIUS/site scripts, but reply rendering falls back to the configured global compatibility packs.

Example:

```yaml
radius:
  clients:
    - ip: 10.20.0.2
      secret: "ap-secret-01"
      shortname: "ap-lobby-01"
      nas_type: "aruba"
    - ip: 10.20.0.3
      secret: "ap-secret-02"
      shortname: "ap-lobby-02"
      nas_type: "ubnt"
```

The same profile can be set from the appliance CLI:

```bash
/opt/aegisnas/bin/aegis-radius client add ap-lobby-01 10.20.0.2 'ap-secret-01' --nas-type aruba
/opt/aegisnas/bin/aegis-radius client list
```

### 7. Validate The Appliance Config

Run:

```bash
/opt/aegisnas/bin/aegis-admin validate-config --config /etc/aegisnas/config.yaml
```

Then inspect the generated RADIUS config:

```bash
/opt/aegisnas/bin/aegis-radius gen-config --config /etc/aegisnas/config.yaml
```

You should now see:

- `clients.conf`
- `dictionary`
- `aegisnas-vendor.dictionery`
- `eap.conf`
- `mods-enabled/ldap`
- `mods-enabled/sql`
- `proxy.conf`
- `sites-enabled/default`
- `sites-enabled/inner-tunnel`

### 8. Apply The RADIUS Config

Run:

```bash
sudo /opt/aegisnas/bin/aegis-radius apply-config --config /etc/aegisnas/config.yaml
```

This writes the generated files into the FreeRADIUS config directory, runs `freeradius -XC`, and restarts the service.

### 9. Verify Upstream AAA Reachability

Check the appliance logs:

```bash
journalctl -u aegis-radius -n 100 --no-pager
journalctl -u freeradius -n 100 --no-pager
```

Verify the rendered proxy file exists:

```bash
sudo ls -l /etc/freeradius/3.0/proxy.conf
sudo sed -n '1,220p' /etc/freeradius/3.0/proxy.conf
sudo sed -n '1,220p' /etc/freeradius/3.0/dictionary
sudo sed -n '1,220p' /etc/freeradius/3.0/aegisnas-vendor.dictionery
```

### 10. Test Authentication

From a test AP, switch, or supplicant flow:

1. send a known-good login
2. confirm the upstream AAA server sees the request from AegisNAS
3. confirm the access device receives `Access-Accept`
4. confirm session visibility on AegisNAS

If using the captive portal:

1. enable `portal.radius_auth: true`
2. perform a portal login with a user that exists only on the upstream AAA system
3. confirm the session is created locally with the expected role, VLAN, and timeouts

### 11. Test Accounting

Confirm the upstream AAA platform receives:

- `Accounting-Start`
- `Accounting-Interim-Update` from access devices or from the local session service
- `Accounting-Stop`

Also check local appliance visibility in sessions and logs.

### 12. Test Dynamic Authorization

From the upstream AAA platform or a RADIUS test tool:

1. send a `Disconnect-Request` for an active `Acct-Session-Id`
2. confirm the session disappears from the session API and portal state
3. re-authenticate the client
4. send a `CoA-Request` that changes `Filter-Id`, VLAN, or timeout attributes
5. confirm the session record updates locally

The default dynamic authorization listener port is `3799/udp`.

### 13. Test Failover

If you configured multiple upstream servers:

1. stop or block the primary server
2. trigger a fresh authentication
3. confirm the request is sent to the secondary
4. restore the primary
5. confirm it becomes usable again according to your health-check mode

## Ubuntu Appliance Notes

For Ubuntu deployment, combine this guide with:

- [ubuntu-appliance-deployment.md](F:/random_project/Pookie/aegisnas-pi4/docs/ubuntu-appliance-deployment.md)
- [operations.md](F:/random_project/Pookie/aegisnas-pi4/docs/operations.md)
- [security.md](F:/random_project/Pookie/aegisnas-pi4/docs/security.md)
- [aaa-product-implementation-notes.md](F:/random_project/Pookie/aegisnas-pi4/docs/aaa-product-implementation-notes.md)

The appliance package prerequisites remain the same, but now the commissioning checklist must capture upstream AAA, reply-attribute mapping, and dynamic authorization details.

## Rollback

To return to local-only RADIUS behavior:

1. set `radius.upstream.enabled: false`
2. set `portal.radius_auth: false` if you want the portal to stay local-only
3. re-run config validation
4. re-run `aegis-radius apply-config`
5. retest login and accounting

Because `proxy.conf` is generated on every apply, rollback is straightforward and does not require hand-editing FreeRADIUS files.

## Future Maintainer Notes

This section is here on purpose so future work is easy to pick back up.

### Files To Revisit Next

- [generator.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/generator.go)
- [auth.go](F:/random_project/Pookie/aegisnas-pi4/internal/portal/auth/auth.go)
- [server.go](F:/random_project/Pookie/aegisnas-pi4/internal/portal/server/server.go)
- [manager.go](F:/random_project/Pookie/aegisnas-pi4/internal/sessions/manager.go)
- [dynamic_auth.go](F:/random_project/Pookie/aegisnas-pi4/internal/sessions/dynamic_auth.go)
- [mapping.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/mapping.go)
- [aaa-product-implementation-notes.md](F:/random_project/Pookie/aegisnas-pi4/docs/aaa-product-implementation-notes.md)

### Most Likely Next Enhancements

1. add optional policy for which local users are allowed during upstream outage
2. add storage NAS services as a separate product layer when needed

### Engineering Intent

The current implementation keeps the product shape conservative:

- the appliance owns the edge
- FreeRADIUS handles upstream protocol interoperability
- upstream AAA remains the source of identity truth
- the Go services stay responsible for UI, state, policy, and operations

That division keeps the product maintainable and makes enterprise interop much less brittle.
