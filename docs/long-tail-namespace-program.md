# NAS-0072 Long-Tail Typed Namespace Program

NAS-0072 software-certifies typed handling for the remaining in-corpus vendor
namespaces assigned to the long-tail roadmap wave. It covers 92 FreeRADIUS
3.2.8 vendor namespaces and 1,126 pinned VSA rows.

The program does not claim exact hardware behavior for every named vendor. It
establishes the production software boundary: deterministic dictionary
classification, bounded packet decoding, safe inbound normalization, redacted
secret evidence, release-scoped reporting, durable evidence, API/UI visibility,
readiness checks, support bundles, and CI gates.

## Supported Software Scope

NAS-0072 covers the following FreeRADIUS dictionary namespaces:

```text
Actelis, Adtran, Adva, Airespace, APC, Aptilo, Arbor, AudioCodes,
Big-Switch-Networks, BlueCoat, Boingo, Bristol, BT, Cajun_p330, Camiant,
Centec, Ciena, Citrix, Ckey, Compatible, Cosine, Covaro, DANTE, Digium,
DragonWave, EfficientIP, Eleven, F5, FreeRADIUS, Garderos, Gemtek,
IEA-Software, Infinera, Infoblox, infonet, ipUnplugged, KarlNet, Kineto,
Lancom, Lantronix, Livingston, Local-Web, Meinberg, Mellanox, Merit, Meru,
Microsemi, Mimosa, NetworkPhysics, Nile, Nomadix, Nortel, NTUA, Packeteer,
Perle, pfSense, Pica8, Prosoft, Proxim, Purewave, Quiconnect, RCNTEC,
RedCreek, Riverbed, Riverstone, Roaring-Penguin, RuggedCom, Shasta, Siemens,
Slipstream, SmartShareSystems, SoftBank, SpringTide, Surfnet, Symbol, Telebit,
Telkom, Telrad, TERENA, Trapeze, TrippLite, Tropos, T-Systems-Nova, UKERNA,
Unix, Versanet, Walabi, Waverider, WISPr, Xylan, Yubico, Zeus
```

The typed namespace program classifies rows into neutral AegisNAS semantics
where the dictionary name provides a reliable production signal:

- role, group, privilege, policy tag, and tenant context
- VLAN, tunnel, fabric, VRF, route, IPv4, IPv6, and address-pool context
- bandwidth, QoS, quota, accounting, and session-limit evidence
- ACL, filter, firewall profile, captive portal, hotspot, and guest hints
- device group, controller, AP, wireless posture, certificate, token, and key
  context
- CoA/Disconnect lifecycle semantics for attributes that describe dynamic
  action, remediation, disconnect, or reauthorization behavior
- typed pass-through evidence for vendor-specific rows without safe native
  semantics

Sensitive attribute names such as token, password, key, secret, certificate,
challenge, and private material are decoded as bounded evidence and redacted
before persistence, support-bundle capture, or UI/API display.

## API

```text
GET  /api/v1/system/long-tail-namespaces
POST /api/v1/system/long-tail-namespaces/record
GET  /api/v1/system/long-tail-namespaces/history
```

The `GET` endpoint returns the generated software certification report and
recent evidence. The `POST` endpoint records the current source hash,
fingerprint, counts, summary JSON, full report JSON, actor, and timestamp in
`long_tail_namespace_events`. The history endpoint returns durable evidence
used by readiness checks and support bundles.

## Configuration

The long-tail pack is not enabled by default. Enable it only for explicit
interop, migration, or lab scopes where the peer is known:

```yaml
radius:
  vendor:
    compatibility_packs:
      - standard
      - aegisnas
      - long-tail
```

Aliases accepted for configuration and release profile lookup include
`long-tail`, `longtail`, `long-tail-namespace`, `long-tail-namespaces`,
`typed-long-tail`, `typed-longtail`, and `nas-0072`.

Focused packs keep their existing pack keys. For example, an Airespace row that
already belongs to the Cisco family still uses the Airespace pack. NAS-0072
adds software certification and typed handling for the long-tail program
without moving established mappings out of their focused pack.

## Packet Processing

Inbound VSAs are decoded through the generated FreeRADIUS registry and shared
VSA codec. The runtime profile assigns a decoder for every valid type code in
the NAS-0072 scope and records explicit external-certification state.

`internal/radius/long_tail_namespace.go` maps safe values into neutral
authorization, accounting, posture, tenant, device, ACL, bandwidth, address,
portal, and policy fields. Unknown-but-safe long-tail values are retained only
as bounded evidence strings. Sensitive values are represented as
`<redacted:digest>` and never persisted in clear text.

Malformed packets remain fail-closed through the shared codec. Opaque
pass-through remains separate and must be explicitly allowed by
`radius.vendor.opaque_pass_through`; NAS-0072 typed handling does not turn on
blind forwarding.

## Operations

Inspect the current software certification report:

```bash
curl -fsS \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/long-tail-namespaces | jq '.report.summary'
```

Record the current build fingerprint after automated tests pass:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/long-tail-namespaces/record | jq '.event_id, .status'
```

Run the software gate locally or in CI:

```bash
make test-long-tail-namespace
```

Production readiness reports the `long_tail_namespace_program` check, system
status embeds `radius.long_tail_namespace_program`, and support bundles include
`api/long-tail-namespaces.json` plus
`api/long-tail-namespaces-history.json`.

## Release Boundary

Software implementation is complete when automated tests, API, UI,
configuration, packet processing, database migration, CI, and documentation
pass. Physical devices, controllers, FreeRADIUS production Linux imports, HA
drills, performance, soak, security audit, production deployment, compliance,
and customer proof are tracked in
`docs/nas-0072-release-certification-checklist.md`.

