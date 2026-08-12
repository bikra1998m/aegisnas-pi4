# Dual-stack Shaping And Vendor Rate Compiler

NAS-0052 completes the software path for dual-stack bandwidth enforcement and
vendor unit-safe rate rendering. Runtime QoS now shapes IPv4-only, IPv6-only,
and dual-stack sessions, and the rate compiler produces bounded RADIUS values
for vendors that expect different units or grammar.

## Scope

Implemented software scope:

- IPv4 `tc u32` classifiers remain supported for download and upload shaping.
- IPv6-only and dual-stack sessions now receive `tc flower` download and upload
  classifiers.
- IFB ingress redirection is installed for both IPv4 and IPv6 traffic.
- Runtime QoS summaries include IPv4, IPv6, and IPv6-only session counts.
- Leaf classes record `address_family`, IPv4 address, and IPv6 address metadata.
- Shared rate helpers enforce 32-bit RADIUS integer bounds.
- MikroTik `Mikrotik-Rate-Limit` supports basic and extended rate grammar.
- Observed rate attributes can be decompiled back into normalized kbps intent.
- WISPr and shared vendor packs render integer kbps values.
- UBNT renders integer bps values from normalized kbps with overflow checks.
- Huawei, H3C, TPLink, ZTE, Cambium, Airespace, HP, Nomadix, ChilliSpot, and
  D-Link use the same unit-safe kbps compiler.
- Outbound RADIUS replies and CoA vendor actions use the shared rate helpers.
- Admin API, OpenAPI, RBAC, production-readiness, support-bundle, system-status,
  Dashboard, and schema evidence are implemented.

External Linux `tc`, packet-capture, FreeRADIUS, vendor/controller, HA,
throughput, soak, security, production deployment, and customer validation are
tracked in `nas-0052-release-certification-checklist.md`.

## Vendor Units

The compiler accepts normalized kbps intent and emits vendor-specific values:

| Vendor pack | Attributes | Unit |
|---|---|---|
| MikroTik | `Mikrotik-Rate-Limit` | RouterOS rate grammar |
| WISPr | `WISPr-Bandwidth-Max-Down`, `WISPr-Bandwidth-Max-Up` | integer kbps |
| UBNT | `UBNT-Data-Rate-DL`, `UBNT-Data-Rate-UL` | integer bps |
| Huawei | `Huawei-Output-Average-Rate`, `Huawei-Input-Average-Rate` | integer kbps |
| H3C | `H3C-Output-Average-Rate`, `H3C-Input-Average-Rate` | integer kbps |
| TPLink | `TPLink-Xmit-limit`, `TPLink-Recv-limit` | integer kbps |
| ZTE | `Rate-Ctrl-SCR-Down`, `Rate-Ctrl-SCR-Up` | integer kbps |

Other shared kbps packs use the same bounds and formatting path.

## API

Read compiler coverage and evidence:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/rate-compiler \
  | jq '.report.capabilities, .evidence.summary'
```

Compile vendor-safe rate attributes:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "pack_keys": ["mikrotik", "wispr", "ubnt", "huawei", "h3c", "tplink", "zte"],
    "download_rate_kbps": 50000,
    "upload_rate_kbps": 20000,
    "download_burst_rate_kbps": 80000,
    "upload_burst_rate_kbps": 30000,
    "download_burst_threshold_kbps": 40000,
    "upload_burst_threshold_kbps": 10000,
    "download_burst_time_seconds": 10,
    "upload_burst_time_seconds": 10,
    "priority": 3,
    "download_min_rate_kbps": 10000,
    "upload_min_rate_kbps": 5000
  }' \
  http://127.0.0.1:8083/api/v1/system/rate-compiler/compile \
  | jq '.event_id, .result.status, .result.attributes'
```

Decompile observed vendor attributes back into normalized intent:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "pack_key": "ubnt",
    "attributes": [
      {"name": "UBNT-Data-Rate-DL", "value": "50000000"},
      {"name": "UBNT-Data-Rate-UL", "value": "20000000"}
    ]
  }' \
  http://127.0.0.1:8083/api/v1/system/rate-compiler/decompile \
  | jq '.event_id, .result.status, .result.intent'
```

## Runtime Shaping

The QoS scheduler keeps the NAS-0051 hierarchy and adds IPv6 classifiers:

- IPv4 download: `tc filter ... protocol ip ... u32 match ip dst <addr>/32`
- IPv4 upload: `tc filter ... protocol ip ... u32 match ip src <addr>/32`
- IPv6 download: `tc filter ... protocol ipv6 ... flower dst_ip <addr>`
- IPv6 upload: `tc filter ... protocol ipv6 ... flower src_ip <addr>`

Use the existing QoS scheduler preview before applying:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/qos-scheduler/preview \
  | jq '.plan.summary, .plan.commands[] | select(test("ipv6|flower"))'
```

## Database

Schema v57 adds `rate_compiler_events`.

Each event stores:

- event ID
- operation and status
- pack keys JSON
- normalized download and upload kbps
- attribute and diagnostic counts
- request, response, and diagnostics JSON
- compile and decompile operation status
- actor and creation time

## Operations

Support bundles include `api/rate-compiler.json`.

Dashboard includes:

- IPv4, IPv6, and IPv6-only QoS session counts
- Vendor Rate Compiler status
- compiler version
- supported unit-profile count
- compile evidence counters

## Validation

Automated software validation covers:

- rate unit helpers and RADIUS integer bounds
- MikroTik basic and extended grammar
- UBNT bps overflow blocking
- IPv6-only and dual-stack QoS command planning
- DB migration and rate compiler evidence
- API status, compile, readiness, RBAC, OpenAPI, and support bundle behavior
- Dashboard build integration

Release certification covers host `tc flower` support, traffic captures,
FreeRADIUS and vendor-device interoperability, controller reconciliation,
throughput, latency, HA, soak, security review, and production acceptance.
