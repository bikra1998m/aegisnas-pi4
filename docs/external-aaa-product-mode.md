# External AAA Product Mode

For untrusted or cross-site networks, configure upstream servers with
`transport: radsec` and follow [radsec.md](radsec.md). RadSec peers fail closed
and never downgrade automatically to UDP. Upstream RadSec peers can use either
X.509 mTLS or explicitly negotiated TLS-PSK with redacted secret references and
active-window rotation. Use [radius-transport-policy.md](radius-transport-policy.md)
to keep route pools from silently mixing RadSec and UDP.

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
- [radsec_credentials.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/radsec_credentials.go)
- [transport_policy.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/transport_policy.go)
- [client.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/client.go)
- [vendor.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/vendor.go)
- [accounting.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/accounting.go)
- [mapping.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/mapping.go)
- [dynamic_nas_clients.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/dynamic_nas_clients.go)
- [manager.go](F:/random_project/Pookie/aegisnas-pi4/internal/sessions/manager.go)
- [dynamic_auth.go](F:/random_project/Pookie/aegisnas-pi4/internal/sessions/dynamic_auth.go)
- [framework.go](F:/random_project/Pookie/aegisnas-pi4/internal/eap/framework.go)
- [teap.go](F:/random_project/Pookie/aegisnas-pi4/internal/eap/teap.go)
- [eap_framework.go](F:/random_project/Pookie/aegisnas-pi4/internal/adminapi/eap_framework.go)
- [webauthn.go](F:/random_project/Pookie/aegisnas-pi4/internal/webauthn/webauthn.go)
- [webauthn.go](F:/random_project/Pookie/aegisnas-pi4/internal/adminapi/webauthn.go)
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
12. records and approves dynamic AP, switch, gateway, and controller NAS clients before allowing them to send trusted RADIUS traffic
13. supports outbound RadSec TLS-PSK peers with secret-reference validation, deterministic rotation, redacted status, and production readiness checks
14. blocks downgrade-prone mixed UDP/RadSec proxy pools when transport policy is in enforce mode
15. governs portal local/LDAP fallback during upstream outage with identity allowlists, bounded outage windows, hashed audit events, readiness checks, and dashboard/API visibility
16. supports MAC Authentication Bypass endpoint state, profile-linked quarantine, generated FreeRADIUS authorize entries, API evaluation, dashboard status, and readiness checks for non-802.1X devices
17. protects privileged admin token and SSO sessions with WebAuthn/passkey step-up, credential lifecycle APIs, dashboard status, readiness checks, and support-bundle evidence
18. governs EAP methods through a typed framework for PEAP, TTLS, TLS, identity-source binding, Message-Authenticator requirements, planned-method blockers, API evaluation, dashboard status, and support-bundle evidence
19. generates opt-in TEAP policy with RFC 7170 method chaining, machine/user identity requirements, cryptobinding checks, PAC governance, API evaluation, dashboard status, and support-bundle evidence

## Current Behavior

When `radius.upstream.enabled: true`:

- inbound RADIUS auth requests are proxied to the configured upstream pool
- inbound RADIUS accounting requests are proxied to the configured upstream pool
- captive portal web logins can use the same broker path through `portal.radius_auth: true`
- upstream server failover and load distribution are handled by FreeRADIUS
- APs and switches can use the dynamic NAS enrollment API when `radius.dynamic_clients.enabled: true`
- unknown packet sources can be recorded as pending discovery evidence when packet discovery is enabled, but they remain rejected until approved
- portal sessions keep a stable `Acct-Session-Id`
- the session service sends interim accounting on the configured interval
- the session service listens on `radius.dynamic_auth.port` for dynamic authorization
- the dashboard probes each upstream AAA home server directly with `Status-Server` when that mode is enabled
- TLS-PSK RadSec peers expose credential and rotation state through `/api/v1/system/radsec-credentials`; active transport proof remains part of the release certification checklist because the local Go probe path is mTLS-only
- transport policy exposes route-level downgrade risk through `/api/v1/system/transport-policy` and prevents proxy generation when enforce mode would be violated
- fallback policy exposes local/LDAP outage behavior through `/api/v1/system/fallback-policy`; enforce mode denies fallback unless source, identity allowlist, and outage window policy all match
- the gateway rebuilds Linux `tc` shaping for any active session with a named bandwidth profile
- the vendor reply preview can render vendor-neutral ACL intent into `NAS-Filter-Rule`, Cisco `Cisco-AVPair`, Aruba filter rules, MikroTik address-list hints, and AegisNAS ACL VSAs
- MAB endpoints can be approved, denied, quarantined, expired, or left pending; approved and quarantined endpoints render MAC variants into FreeRADIUS `files/authorize`
- unknown MAB endpoints can deny, enter guest, enter quarantine, or explicitly fail open based on `mab.unknown_endpoint_policy`
- upstream reply attributes are mapped into local session state:
  - VLAN assignment
  - role mapping
  - bandwidth profile mapping
  - `Filter-Id` preservation
  - session timeout
  - idle timeout
  - AegisNAS vendor-specific attributes when `radius.vendor.enabled: true`
  - enabled compatibility-pack VSAs such as Aruba role/VLAN, Ruckus groups/VLAN, Fortinet profiles, Cisco/Juniper ACL names, UniFi/UBNT rate hints, Cambium rate/VLAN/quarantine, Meraki context, Extreme Netlogin, Huawei/H3C QoS, Palo Alto context, and TP-Link Omada hints
- break-glass local admin auth remains available even when portal RADIUS auth is enabled
- privileged admin token and SSO sessions can require WebAuthn/passkey assertion before the admin API accepts a verified session token
- EAP framework state is available through `/api/v1/system/eap-framework`; enforce/fail-closed mode prevents generated FreeRADIUS config when planned methods such as FAST, PWD, SIM, AKA, or AKA-prime are enabled before their roadmap feature lands
- TEAP method-chain state is available through `/api/v1/system/eap-framework/teap`; when `teap` is added to `radius.eap.framework.allowed_methods`, generated FreeRADIUS includes a conservative `teap` block and AegisNAS evaluates cryptobinding, Identity-Type, PAC, machine identity, and user identity policy
- voucher logins remain local so guest access still has an offline path

What this pass still does not change:

- storage NAS services such as Samba, NFS, RAID, ZFS, and share management are still separate workstreams
- reusable ACL policies are not yet persisted as first-class database objects
- `CoA-Request` can now trigger immediate gateway quarantine enforcement, immediate timeout expiry, live bandwidth profile reshaping, and VLAN-change reauthentication, but live controller/device ACL push still needs per-vendor smoke testing
- `scripts/vendor-certification-lab.sh` provides the repeatable per-pack API, RADIUS, packet-capture, real-device, controller, upgrade, and rollback evidence workflow for that smoke testing
- real AP/switch/controller certification for MAB remains tracked in [nas-0017-release-certification-checklist.md](nas-0017-release-certification-checklist.md)
- real authenticator, browser, SSO provider, HA, and security validation for admin passkeys remains tracked in [nas-0021-release-certification-checklist.md](nas-0021-release-certification-checklist.md)
- real supplicant, AP/controller, packet-capture, FreeRADIUS-on-Linux, HA, and performance validation for EAP remains tracked in [nas-0022-release-certification-checklist.md](nas-0022-release-certification-checklist.md)
- real TEAP supplicant, AP/controller, packet-capture, FreeRADIUS-on-Linux, HA, performance, and security validation remains tracked in [nas-0023-release-certification-checklist.md](nas-0023-release-certification-checklist.md)

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
    id: 55555 # Lab placeholder from configs/dictionary.aegisnas. Replace before production use.
    dictionary_release: "freeradius-3.2.8"
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
    accounting_spool:
      enabled: true
      max_queue_records: 10000
      max_attempts: 10
      initial_retry_seconds: 30
      max_retry_seconds: 3600
      record_ttl_seconds: 604800
      replay_interval_seconds: 60
      batch_size: 100
      lock_seconds: 120
      sent_retention_seconds: 604800
      poison_retention_seconds: 2592000
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
- `accounting_spool.enabled: true` persists failed proxy accounting records for bounded replay, poison handling, and operator audit
- `radius.vendor.id` must be your own verified IANA Private Enterprise Number for production; keep `55555` only for lab testing.
- IANA PEN registration is free and first-come-first-served. Request the assignment from <https://www.iana.org/assignments/enterprise-numbers/assignment/apply/>, wait for the registry entry, then use the Vendor Compatibility preview/apply workflow. Direct settings updates to vendor identity fields are rejected.
- During migration, outbound VSAs use the assigned PEN immediately. `radius.vendor.legacy_ids` are inbound-only and expire at `radius.vendor.legacy_accept_until`.
- `aegis-radius apply-config` writes `/etc/freeradius/3.0/dictionary.aegisnas` and includes it from the local FreeRADIUS `dictionary`

### 4. Configure AegisNAS Vendor Attributes

AegisNAS can behave like a vendor NAS by publishing its own FreeRADIUS product dictionary and parsing its own Vendor-Specific Attributes. The product dictionary is the source of truth for built-in attribute names, numbers, and types.

The portable product dictionary template is:

- [dictionary.aegisnas](F:/random_project/Pookie/aegisnas-pi4/configs/dictionary.aegisnas)

On an appliance, `aegis-radius apply-config` writes:

- `/etc/freeradius/3.0/dictionary`
- `/etc/freeradius/3.0/dictionary.aegisnas`

The generated `dictionary` file contains:

```text
$INCLUDE dictionary.aegisnas
```

To see the current built-in attributes, read the dictionary instead of copying the list into YAML:

```bash
sed -n '1,220p' configs/dictionary.aegisnas
```

For package or VM installs, the helper below writes the dictionary and include line. It refuses the placeholder ID unless `--allow-placeholder` is provided for a lab:

```bash
sudo bash scripts/install-aegisnas-freeradius-dictionary.sh \
  --vendor-id <assigned-pen> \
  --organization '<exact organization from IANA>'
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

To scan a FreeRADIUS dictionary tree from the appliance shell and generate the same compatibility matrix:

```bash
aegis-admin scan-radius-dictionaries \
  --dictionary /etc/freeradius/3.0/dictionary \
  --dictionary /usr/share/freeradius
```

For automation, export the full scanner report as JSON or the pack matrix as CSV:

```bash
aegis-admin scan-radius-dictionaries --json > vendor-dictionary-scan.json
aegis-admin scan-radius-dictionaries --matrix-csv > vendor-dictionary-matrix.csv
```

The scanner reports:

- supported attributes: AegisNAS semantic mappings already marked `implemented`
- planned attributes: known vendor mappings that still need renderer, parser, controller, or hardware validation work
- ignored attributes: parsed FreeRADIUS dictionary attributes that are not yet mapped into AegisNAS vendor-neutral semantics

To preview the exact reply attributes for a profile before testing hardware:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"nas_type":"aruba","role":"guest","vlan":20,"download_kbps":50000,"upload_kbps":20000}' \
  http://127.0.0.1:8083/api/v1/system/vendor-reply-preview | jq '.nas_type, .effective_packs, .attributes, .warnings'
```

Dynamic ACL intent uses the same preview endpoint. Submit `acl_policy_name`, optional named inbound/outbound ACLs, and `acl_rules`; the response includes `normalized_acl_rules` and `acl_exports` for each effective pack. Rule-based exports include standard `NAS-Filter-Rule`, Cisco `Cisco-AVPair` downloadable ACL lines, Aruba filter rules, AegisNAS product ACL rules, and vendors such as D-Link/Pica8/HP where line rules are represented directly. Profile-style exports such as MikroTik address lists, Fortinet access profiles, and Ruckus user groups return profile hints with warnings when line rules still need controller-side policy.

Applied ACL intent can also be kept in the ACL Policies admin page or managed through `/api/v1/acl-policies`. Create or update operations are staged, validated, and committed through `/api/v1/apply`; revision snapshots include the policy library for rollback. After apply, a preview request can supply only `acl_policy_name` to load its rules and named vendor profiles. The response field `acl_policy_loaded` confirms whether persisted content was used.

Assign a stored ACL to a role or policy rule with `acl_policy_name`. Policy evaluation returns the binding, portal sessions persist it, and inbound CoA maps vendor ACL names back to a stored policy when possible. Role bindings also feed generated local FreeRADIUS user entries, including `NAS-Filter-Rule` and every enabled compatibility-pack attribute. Run **Apply RADIUS Config** after changing local users, roles, ACL contents, or compatibility packs; staged database apply alone does not rewrite `mods-config/files/authorize`. Bcrypt-backed local users authenticate with PAP or EAP-TTLS/PAP, not CHAP or PEAP-MSCHAPv2.

The catalog layer reads FreeRADIUS-style `VENDOR`, `BEGIN-VENDOR`, `ATTRIBUTE`, and `VALUE` directives. The semantic layer is the product contract above that catalog. The dictionary coverage matrix compares parsed dictionary attributes with the compatibility packs, then reports whether each pack is `standard-radius`, `dictionary-backed`, `partial-dictionary`, `dictionary-missing`, or `controller-api`. Vendor compatibility packs should map Cisco, Aruba, MikroTik, Ruckus, Fortinet, UniFi, Cambium, Extreme, Juniper, Huawei, H3C, Palo Alto, TP-Link, Aerohive, Airespace, HP, Nomadix, ChilliSpot, D-Link, SonicWall, Arista, Pica8, ZTE, Nokia, Meru, Colubris, OpenWiFi, Mist, and site-specific VSAs into these AegisNAS semantic keys instead of hard-coding controller behavior directly in policy code.

Runtime observability closes the loop between dictionary coverage and real NAS behavior:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-observability | jq '.summary, .vendors[] | select(.unsupported_attribute_count > 0)'
```

Use the compatibility matrix to decide what should be supported, then use vendor observability to track auth outcomes, parsed VSAs, unsupported attributes, CoA or disconnect failures, and the per-vendor NAS compatibility score after live AP, switch, or controller tests.

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

Numeric role and privilege attributes require an explicit reversible mapping. Use only values certified for the target dictionary and device profile:

```yaml
radius:
  vendor:
    compatibility_packs: [standard, dlink, sonicwall]
    role_mappings:
      - pack: dlink
        role: network-admin
        value: 5
      - pack: sonicwall
        role: guest
        value: 7
```

Mappings are supported for `cambium`, `aerohive`, `dlink`, `sonicwall`, and `zte`. Role names and numeric values must each be unique within a pack. AegisNAS omits the numeric reply when no mapping exists and ignores an inbound numeric role that cannot be reversed, avoiding accidental privilege assignment.

Extreme Switch Engine VSA 211 supports one untagged VLAN and multiple tagged VLANs in a single atomic assignment. Configure the IDs per local role:

```yaml
radius:
  vendor:
    compatibility_packs: [standard, extreme]
    extended_vlan_mappings:
      - pack: extreme
        role: voice-device
        untagged_vlan: 20
        tagged_vlans: [30, 40]
```

AegisNAS validates VLAN IDs, rejects duplicates, and enforces Extreme's ten-VLAN limit. The example renders `Extreme-Netlogin-Extended-Vlan = "U20;T30;T40"`. When a matching mapping exists, the extended VSA replaces the lower-priority Extreme VLAN name and VLAN tag attributes. Inbound numeric VSA 211 assignments are parsed back into one untagged VLAN and the tagged VLAN list; name and wildcard forms remain untouched because they cannot be mapped safely into numeric policy intent.

Juniper, Huawei, H3C, and Arista AVPair strings vary by device family and firmware. Configure only values validated against the target device:

```yaml
radius:
  vendor:
    avpair_mappings:
      - pack: juniper
        role: guest
        values: ["firewall=${inbound_acl}", "vlan=${vlan}"]
      - pack: arista
        role: network-admin
        values: ["shell:roles=${role}"]
```

Supported placeholders are `${role}`, `${acl_policy}`, `${inbound_acl}`, `${outbound_acl}`, `${vlan}`, `${policy_tag}`, `${device_group}`, and `${tenant}`. Each role can emit up to 16 values. Unknown placeholders, duplicate values, control characters, and oversized values are rejected. Inbound AVPairs are retained as separate opaque broker context and are not automatically trusted as executable ACL intent.

The FreeRADIUS TP-Link dictionary defines `TPLink-Portal-Access-Status` as integer attribute 9 without portable value labels. Map only values certified against the deployed Omada release:

```yaml
radius:
  vendor:
    portal_status_mappings:
      - pack: tplink
        portal_profile: https://portal.example.test/guest
        value: 1
```

When that portal URL is selected, AegisNAS emits the configured integer alongside the redirect URL. Inbound status values are reversed to the local portal profile only when an exact mapping exists. Profile names and integer values must each be unique, preventing ambiguous authorization state.

The Nomadix dictionary defines `Nomadix-EndofSession` as integer attribute 9 without portable units or labels. Bind a value certified against the target Nomadix firmware to a local role and AegisNAS session action:

```yaml
radius:
  vendor:
    session_action_mappings:
      - pack: nomadix
        role: expired-guest
        action: disconnect
        value: 1
```

Supported actions are `allow`, `reauth`, `disconnect`, and `quarantine`. A role has one outbound mapping. Multiple roles may share a value only when it maps to the same action; conflicting reverse meanings are rejected. Unknown inbound values are ignored. The Nomadix pack uses the official FreeRADIUS names, including `Nomadix-Bw-Up`, `Nomadix-Bw-Down`, `Nomadix-URL-Redirection`, `Nomadix-Net-VLAN`, and `Nomadix-Qos-Policy`.

ChilliSpot combined input and output quotas use `ChilliSpot-Max-Total-Octets`, integer attribute 3. Configure the byte limit by local role:

```yaml
radius:
  vendor:
    quota_mappings:
      - pack: chillispot
        role: guest-1g
        max_total_octets: 1073741824
```

Values must be between 1 and 4,294,967,295 bytes. The limit is an outbound authorization quota, not an accounting counter. Inbound values are retained as normalized quota intent. The ChilliSpot pack now uses the official prefixed names for bandwidth, configuration, portal allowlist, and quota attributes.

Nokia `Nokia-Service-Name` is octet attribute 3 and uses swapped-nibble binary-coded decimal. Configure decimal digits by local role:

```yaml
radius:
  vendor:
    service_name_mappings:
      - pack: nokia
        role: mobile-data
        service_name: "00123"
```

AegisNAS emits `Nokia-Service-Name = 0x0021f3`. Odd digit counts use an `F` high-nibble pad, exactly as defined by the FreeRADIUS Nokia dictionary. Values are limited to 480 decimal digits, leading zeroes are preserved, and malformed inbound BCD is ignored. The Nokia pack also uses the official `Nokia-User-Profile` and `Nokia-AVPair` names.

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
- `cambium`
- `meraki`
- `extreme`
- `juniper`
- `huawei`
- `h3c`
- `paloalto`
- `tplink`
- `aerohive`
- `airespace`
- `hp`
- `nomadix`
- `chillispot`
- `dlink`
- `sonicwall`
- `arista`
- `pica8`
- `zte`
- `nokia`
- `meru`
- `colubris`
- `openwifi`
- `mist`

Only enable a vendor pack after the AP, switch, controller, or upstream policy system is prepared to consume those attributes. A FreeRADIUS dictionary lets AegisNAS name and render an attribute; it does not guarantee that a device will enforce that attribute.

The `radius.vendor.attributes` list is only for local overrides or extra site-specific VSAs.

The same enabled compatibility packs are also used for inbound parsing of Vendor-Specific Attributes returned by an upstream AAA platform or seen in accounting context. Product AegisNAS VSAs win first; compatibility packs then fill any still-empty normalized fields such as role, VLAN, bandwidth rates, policy tag, portal profile, device group, tenant, device posture, accounting identity, quarantine, and ACL names.

Unknown attributes are not trusted or forwarded by default. If a proxy workflow must preserve a long-tail vendor token before AegisNAS has native semantics for it, configure `radius.vendor.opaque_pass_through` with an explicit `standard`, `vendor`, or `vendor_attribute` allow rule and review `/api/v1/system/opaque-passthrough`. Credential, EAP, tunnel-secret, and packet-integrity attributes are always denied as opaque payloads.

The executable compatibility set includes Meraki AP tags, Palo Alto client OS, Airespace WLAN IDs, Arista profiling, Aerohive client-monitor problem codes, and Meru AP IDs as inbound accounting context. Aerohive problem codes are retained as decimal strings because the vendor dictionary defines the attribute as an integer without portable value labels. Safe outbound additions include HP `Egress-VLANID`, Cambium `Cambium-Walled-Garden-State`, Colubris `Intercept` and `AVPair`, plus Pica8 and Nokia `AVPair` policy tags. These attributes remain opt-in through their vendor packs. Vendor-specific dynamic-ACL grammars remain planned until an operator template or certified encoding is configured.

Example upstream Access-Accept reply:

```text
AegisNAS-Role := "guest-premium"
AegisNAS-Bandwidth-Profile := "50m-down-20m-up"
AegisNAS-VLAN := 20
AegisNAS-Session-Timeout := 3600
AegisNAS-Idle-Timeout := 600
```

Example vendor-neutral ACL preview request:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"nas_type":"cisco","role":"guest","acl_policy_name":"guest-internet","acl_rules":[{"action":"permit","direction":"in","protocol":"tcp","source":"any","destination":"any","destination_port":"443"},{"action":"deny","direction":"out","protocol":"udp","source":"any","destination":"10.0.0.0/24","destination_port":"53"}]}' \
  http://127.0.0.1:8083/api/v1/system/vendor-reply-preview | jq '.attributes'
```

The same `acl_rules` payload renders as standards-based `NAS-Filter-Rule`, Cisco `Cisco-AVPair` `ip:inacl`/`ip:outacl` entries, Aruba `Aruba-NAS-Filter-Rule`, MikroTik `Mikrotik-Address-List` when an ACL policy name is present, and AegisNAS `AegisNAS-ACL-Name` / `AegisNAS-ACL-Rule` VSAs when those packs are active.

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
- `cambium` sends standards-based attributes plus Cambium ePMP VLAN and burst-rate replies
- `extreme` sends standards-based attributes plus Extreme Netlogin VLAN and security-profile replies
- `juniper` or `junos` sends standards-based attributes plus Juniper local-user and filter replies
- `huawei` and `h3c` send standards-based attributes plus role, QoS/rate, and policy replies for their dictionaries
- `paloalto` sends standards-based attributes plus Palo Alto admin/user-group context for firewall or VPN use cases
- `tplink` or `omada` sends standards-based attributes plus TP-Link Omada rate, site, and device-group replies
- `meraki` sends standards-based RADIUS replies and exposes contextual Meraki accounting attributes; the native Dashboard adapter can reconcile existing same-name enterprise SSID slots
- `openwifi` uses standards-based RADIUS enforcement; the native OWGW adapter can reconcile existing same-name enterprise SSIDs by AP serial number or venue UUID

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
- `dictionary.aegisnas`
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
sudo sed -n '1,220p' /etc/freeradius/3.0/dictionary.aegisnas
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

For portal local or LDAP fallback:

1. set `identity.failover.mode: enforce`
2. confirm `/api/v1/system/identity-failover` reports the intended `source_order`
3. block the LDAP directory or upstream identity source
4. trigger portal logins for a known local user, a directory user, and a bad password
5. confirm source decisions are recorded in `identity_source_events`
6. confirm repeated LDAP failures open the circuit and fail closed when no executable source remains
7. export a support bundle and retain `api/identity-failover.json`

For Active Directory Kerberos or winbind identity:

1. set `active_directory.enabled: true`, `active_directory.mode: enforce`, and `active_directory.fail_closed: true`
2. configure `domain`, uppercase `realm`, `ldap_url`, `base_dn`, and either LDAPS bind credentials or Kerberos/winbind verifier settings
3. add `active-directory` to `identity.failover.source_order`
4. confirm `/api/v1/system/active-directory` reports `source_executable: true`
5. run `POST /api/v1/system/active-directory/check` and review recorded health checks
6. trigger portal logins for a valid AD user, a bad password, and a missing user
7. confirm hashed decisions appear in `active_directory_events` and source decisions appear in `identity_source_events`
8. export a support bundle and retain `api/active-directory.json`

For OTP or upstream RADIUS challenge MFA:

1. set `mfa.enabled: true`, `mfa.mode: enforce`, and `mfa.fail_closed: true`
2. set `mfa.otp.sealing_key_ref` to a secure `env:` or `file:` secret
3. enroll a test identity with `POST /api/v1/system/mfa/enroll`
4. perform a portal login for a step-up role and confirm the OTP prompt appears
5. confirm successful OTP creates the session and failed OTP records a denied `mfa_events` entry
6. if the upstream server issues `Access-Challenge`, confirm the broker returns RFC 2865 `State` and the second request includes that state
7. export a support bundle and retain `api/mfa.json`

For admin WebAuthn/passkey step-up:

1. set `admin_webauthn.enabled: true`, `admin_webauthn.mode: monitor`, and configure the production HTTPS `rp_id` and `origins`
2. sign in as `super_admin` and register at least two passkeys for privileged administrators
3. confirm `/api/v1/system/webauthn` reports enabled credentials and no blocking warnings
4. set `admin_webauthn.mode: enforce` and keep `admin_webauthn.fail_closed: true`
5. perform token login and admin SSO login and confirm both require a WebAuthn assertion before protected APIs accept the session
6. revoke one credential and confirm it can no longer complete login
7. export a support bundle and retain `api/webauthn.json`

For the EAP method framework:

1. set `radius.eap.framework.enabled: true`, `mode: monitor`, and configure allowed PEAP, TTLS, and TLS methods
2. confirm `/api/v1/system/eap-framework` reports generated methods and no blocking issues
3. use `POST /api/v1/system/eap-framework/evaluate` with representative method and NAS-type payloads
4. switch to `mode: enforce` and keep `fail_closed: true`
5. run **Apply RADIUS Config** so `mods-enabled/eap` is regenerated and validated
6. test enabled supplicant methods through a real AP or switch
7. export a support bundle and retain `api/eap-framework.json`

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

1. add storage NAS services as a separate product layer when needed

### Engineering Intent

The current implementation keeps the product shape conservative:

- the appliance owns the edge
- FreeRADIUS handles upstream protocol interoperability
- upstream AAA remains the source of identity truth
- the Go services stay responsible for UI, state, policy, and operations

That division keeps the product maintainable and makes enterprise interop much less brittle.
