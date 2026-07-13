# RADIUS Packet Hardening

NAS-0009 adds a fail-closed packet-hardening layer for RADIUS intake and proxy-facing operations.

## What It Protects

- Malformed RADIUS headers, invalid length fields, truncated attributes, oversized packets, and excessive attribute counts.
- Missing or invalid `Message-Authenticator` where required by policy.
- Excessive `Proxy-State` attributes or bytes that can create proxy-loop and memory-pressure risk.
- Packet replay within a bounded replay window.
- Per-source packet bursts that exceed the configured token-bucket rate limit.
- Unknown packet sources that are not configured RADIUS clients, upstream AAA peers, loopback, or explicit trusted CIDRs.
- Unsupported packet codes, including `Status-Client` unless explicitly enabled.

The implementation follows the packet model from RFC 2865, RFC 2869, RFC 5176, RFC 5997, and RFC 6614. Vendor interoperability remains a release-certification activity because it requires packet captures from real NAS, controller, or upstream AAA devices.

## Configuration

```yaml
radius:
  packet_hardening:
    enabled: true
    fail_closed: true
    require_known_source: true
    allow_trailing_padding: false
    allow_status_server: true
    allow_status_client: false
    require_message_authenticator: auto
    max_packet_bytes: 4096
    max_attributes_per_packet: 128
    max_proxy_state_attributes: 8
    max_proxy_state_bytes: 1024
    replay_cache_enabled: true
    replay_window_seconds: 30
    replay_cache_max_entries: 16384
    rate_limit_enabled: true
    per_client_rate_limit_per_second: 250
    per_client_burst: 500
    trusted_proxy_cidrs: []
    event_retention_limit: 6000
```

`require_message_authenticator` supports:

- `auto`: require it for EAP `Access-Request`, `Status-Server`, `CoA-Request`, and `Disconnect-Request`.
- `always`: require it on every accepted packet.
- `never`: disable enforcement. This is degraded for production readiness.

`trusted_proxy_cidrs` is for HA peers, local relays, or proxy subnets that are not already listed under `radius.clients` or `radius.upstream.servers`.

## Runtime Behavior

The shared hardener validates raw RADIUS packets before decode in packet tests and future native listeners. The in-process Dynamic Authorization listener also applies the hardener to decoded `CoA-Request` and `Disconnect-Request` packets before session enforcement.

FreeRADIUS generation now writes the effective `require_message_authenticator` value into generated UDP client and upstream home-server configuration so FreeRADIUS and the AegisNAS hardening policy agree.

## Observability

The admin API exposes:

- `GET /api/v1/system/radius-hardening`
- `GET /api/v1/system/status` under `radius.packet_hardening`
- `GET /api/v1/system/production-readiness` as check `radius_packet_hardening`

Rejected and accepted hardening decisions are persisted in `radius_packet_hardening_events` with bounded retention. Events intentionally do not store packet bodies, shared secrets, `User-Password`, or opaque attribute payloads.

## Operator Flow

1. Configure RADIUS clients, upstream peers, and any trusted proxy CIDRs.
2. Keep `enabled`, `fail_closed`, `require_known_source`, replay cache, and rate limit enabled.
3. Use `auto` for broad production compatibility or `always` for strict test labs.
4. Check `/api/v1/system/radius-hardening` before applying FreeRADIUS config.
5. Review hardening events after enabling new NAS/controller models.
6. Complete the NAS-0009 release certification checklist with real packet captures before customer production sign-off.
