# Dictionary Release, Alias, And Firmware Profiles

Feature: `NAS-0003`

Status: engineering implementation complete; ready for external validation.

## Purpose

NAS-0003 pins the generated registry to an explicit FreeRADIUS dictionary release profile. The profile records release identity, source counts, registry hash, vendor aliases, attribute aliases, firmware scopes, and semantic provenance. This prevents configuration, packet processing, API clients, and operators from silently mixing dictionary generations or vendor spellings.

The active software profile is `freeradius-3.2.8`. It covers the pinned FreeRADIUS 3.2.8 audit source, 246 dictionary files, 7,654 source VSA records, 7,661 effective entries, 196 namespaces, 148 mapped attributes, and 134 runtime decoder mappings.

RFC 2865 defines the Vendor-Specific Attribute envelope. RFC 2866, RFC 5176, RFC 6614, and RFC 9813 are tracked in the profile because accounting, dynamic authorization, RadSec, and RADIUS/1.1 behavior consume the same vendor compatibility surface.

## Software Architecture

`configs.DictionaryReleaseProfile` is an immutable build-time contract. It contains:

- profile ID, FreeRADIUS release, source hash, source/effective counts, and default status;
- canonical vendor aliases such as `unifi` to `Ubiquiti`, `routeros` to `Mikrotik`, `omada` to `TPLink`, `junos` to `Juniper`, and `open-wifi` to `OpenWiFi`;
- attribute aliases for known spelling variants such as `Cisco-AV-Pair`, `Ubiquiti-Data-Rate-DL`, `Huawei-AVPair`, `H3C-AVPair`, and TP-Link spellings;
- firmware profiles for RouterOS, UniFi Network, ArubaOS, Cisco IOS/IOS-XE, Junos, Comware, Omada, Nokia SR OS, and TIP OpenWiFi;
- support state and external evidence state for every firmware scope.

The attribute registry now carries `release_profile_id` and `semantic_provenance` on every entry. Runtime annotations from AegisNAS are marked separately from FreeRADIUS audit metadata. Registry cursors use a `v2` payload bound to the release profile ID, source hash, and normalized filters.

No database migration is required. The release profile is immutable and content-addressed inside the binary, so HA nodes running the same build see the same aliases and firmware scopes. Future mutable evidence records belong to NAS-0004.

## APIs

Read the active and built-in release profiles:

```text
GET /api/v1/system/dictionary-release-profiles
GET /api/v1/system/dictionary-release-profiles?id=freeradius-3.2.8
```

Read the typed registry for a release:

```text
GET /api/v1/system/attribute-registry?release=freeradius-3.2.8
```

The vendor compatibility API includes `dictionary_release_profile` and summary fields:

- `dictionary_release_profile_id`
- `dictionary_release`
- `dictionary_release_source_sha256`

Production readiness adds a `dictionary_release_profile` check. It blocks when the configured release is unknown, counts drift from the embedded registry, aliases point at unknown entries, or firmware profiles reference invalid packs.

## Configuration

Use the pinned release profile in YAML:

```yaml
radius:
  vendor:
    dictionary_release: "freeradius-3.2.8"
```

The value may be omitted. Empty config defaults to `freeradius-3.2.8`. Unknown IDs fail config validation.

## Operator Workflow

1. Confirm `/api/v1/system/production-readiness` reports `dictionary_release_profile` as `passed`.
2. Confirm `/api/v1/system/vendor-compatibility` shows the expected release profile and registry SHA-256.
3. Use canonical pack keys in policy, but aliases such as `unifi`, `routeros`, `omada`, and `open-wifi` are accepted in configuration.
4. Treat `support_state: software-ready` as an engineering claim only. Physical vendor firmware validation remains in the release certification checklist.
5. Compare `dictionary_release_profile.registry_source_sha256` across HA nodes before rolling upgrades.

## Validation

Run:

```bash
make test-dictionary-release-profiles
make test-attribute-registry
```

The tests cover alias normalization, firmware profile validation, registry source hash binding, OpenAPI discovery, RBAC, production readiness, config validation, and vendor compatibility payloads.

## Completion Report

| Measure | Result |
|---|---:|
| Software Implementation | 100% Complete |
| Engineering Implementation | 100% Complete |
| Ready for External Validation | Yes |
| NAS-0003 status | Closed |

There is no remaining NAS-0003 software implementation work. Independent evidence states belong to NAS-0004; grouped, tagged, and repeated VSA codec work belongs to NAS-0005.
