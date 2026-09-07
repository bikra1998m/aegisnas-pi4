# MikroTik RouterOS Pack

NAS-0070 certifies the AegisNAS software implementation for every MikroTik row
in the pinned FreeRADIUS 3.2.8 dictionary audit.

## Scope

- Vendor: `Mikrotik`
- PEN: `14988`
- Dictionary: `dictionary.mikrotik`
- Feature ID: `NAS-0070`
- Attribute rows: `32`
- Software state: `software_certified`
- External state: `external_certification_required`

The pack maps RouterOS PPP, PPPoE, hotspot, simple queue, firewall
address-list, switching-filter, CAPsMAN wireless, DHCP option, IPv4 host, IPv6
delegated-pool, tenant realm, mark-id, and RFC 5176 dynamic authorization
behavior into AegisNAS vendor-neutral semantics.

## Implemented Software Behavior

The generated attribute registry annotates every MikroTik dictionary row with
pack key, semantic ownership, packet direction, decoder type, functionality,
and runtime decoder metadata. Duplicate dictionary aliases are preserved in
the certification report while runtime decoding de-duplicates identical
wire/type/semantic mappings.

Inbound packet processing normalizes:

- `Mikrotik-Rate-Limit` into bandwidth profile plus download and upload kbps
- `Mikrotik-Group` into role/profile intent
- `Mikrotik-Address-List` into inbound ACL profile intent
- `Mikrotik-Switching-Filter` into outbound ACL profile intent
- `Mikrotik-Total-Limit` and `Mikrotik-Total-Limit-Gigawords` into combined
  session total-octet quota
- receive/transmit quota counters into bounded evidence
- `Mikrotik-Realm` into tenant context
- `Mikrotik-Mark-Id` into policy-tag context
- `Mikrotik-Advertise-URL` and `Mikrotik-Advertise-Interval` into hotspot and
  guest portal context
- `Mikrotik-Host-IP` into IPv4 host address context
- `Mikrotik-Delegated-IPv6-Pool` into IPv6 delegated-pool context
- CAPsMAN wireless forwarding, dot1x-skip, encryption algorithm, signal, VLAN,
  and comment fields into posture, VLAN, and device-group context
- DHCP option set and parameter fields into policy-tag and bounded raw evidence
- wireless key material as redacted evidence only

Reply rendering emits RouterOS-safe attributes when the `mikrotik` pack is
active:

- `Mikrotik-Rate-Limit`
- `Mikrotik-Group`
- `Mikrotik-Address-List`
- `Mikrotik-Switching-Filter`
- `Mikrotik-Realm`
- `Mikrotik-Mark-Id`
- `Mikrotik-Advertise-URL`
- `Mikrotik-Host-IP`
- `Mikrotik-Delegated-IPv6-Pool`
- `Mikrotik-Wireless-VLANID`
- `Mikrotik-Wireless-VLANID-Type`
- `Mikrotik-Wireless-Comment`
- `Mikrotik-Total-Limit`
- `Mikrotik-Total-Limit-Gigawords`

The quota renderer splits values larger than `4294967295` into the RouterOS
low-word and gigawords attributes. Non-MikroTik quota packs remain bounded to
their uint32 attribute range.

## Admin API

```text
GET  /api/v1/system/mikrotik-pack
POST /api/v1/system/mikrotik-pack/record
GET  /api/v1/system/mikrotik-pack/history
```

Read-only administrators can view the report and history. Ops and super
administrators can record certification evidence. Recorded events persist in
`mikrotik_pack_events` with release profile, source hash, fingerprint, counts,
summary JSON, full report JSON, actor, and timestamp.

## Monitoring And Readiness

Production readiness includes `mikrotik_pack`. System status exposes the
same software certification summary under `radius.mikrotik_pack`. Support
bundles include:

- `api/mikrotik-pack.json`
- `api/mikrotik-pack-history.json`

## Validation

Run the focused NAS-0070 gate:

```bash
make test-mikrotik-pack
```

The gate covers registry coverage, config validation, packet normalization,
reply rendering, ACL compiler output, dynamic authorization VSA compilation,
database migration and lifecycle, admin API, RBAC, OpenAPI, support-bundle
capture, readiness checks, and admin UI build.

## External Boundary

Engineering completion does not claim physical RouterOS interoperability.
RouterOS hardware, CAPsMAN, PPP/PPPoE, hotspot, CoA/Disconnect ACK/NAK,
FreeRADIUS production Linux, HA, performance, soak, security, production
deployment, and customer acceptance evidence are tracked in
[nas-0070-release-certification-checklist.md](nas-0070-release-certification-checklist.md).
