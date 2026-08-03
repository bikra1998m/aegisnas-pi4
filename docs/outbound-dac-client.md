# Outbound Dynamic Authorization Client

NAS-0042 adds the production software path for sending RFC 5176 Dynamic
Authorization from AegisNAS to managed access devices. Operators can preview and
send vendor-neutral CoA and Disconnect requests, inspect request history, and
collect support evidence without exposing shared secrets or cleartext identity
selectors in persistent history.

## Scope

Implemented software scope:

- CoA-Request and Disconnect-Request packet construction.
- UDP DAC target resolution from managed RADIUS clients, request fields, and
  local session hints.
- Per-NAS shared-secret resolution through inline secrets or configured secret
  references.
- Message-Authenticator on every outbound packet.
- Vendor-neutral selectors and policy attributes:
  `User-Name`, `Acct-Session-Id`, `Calling-Station-Id`, `NAS-Identifier`,
  `NAS-IP-Address`, `Framed-IP-Address`, `Filter-Id`, `Session-Timeout`,
  `Idle-Timeout`, `Reply-Message`, `Class`, `State`, `Tunnel-Type`,
  `Tunnel-Medium-Type`, and `Tunnel-Private-Group-Id`.
- Confirmation gating, known-client gating, timeout limits, attribute limits,
  ACK/NAK/error classification, Error-Cause capture, latency capture, request
  and response fingerprints, runtime status, production readiness, support
  bundle captures, OpenAPI, RBAC, and Access Settings controls.

Deferred roadmap scope:

- NAS-0043 adds durable retry queues, duplicate suppression, expiry, dead-letter
  handling, and idempotency controls.
- NAS-0044 adds proxy CoA and RadSec reverse dynamic authorization routing.
- NAS-0045 adds certified vendor-specific dynamic action compilers.
- NAS-0046 adds authoritative NAS capability and session ownership registry.
- NAS-0047 adds HA-aware cluster handoff.

## Configuration

```yaml
radius:
  dynamic_auth:
    enabled: true
    port: 3799
    outbound_enabled: true
    outbound_default_port: 3799
    outbound_timeout_seconds: 5
    outbound_require_known_client: true
    outbound_history_limit: 10000
    outbound_max_attributes: 32
    outbound_allow_coa: true
    outbound_allow_disconnect: true
    outbound_require_confirmation: true
```

Production deployments should keep `outbound_require_known_client` and
`outbound_require_confirmation` enabled. Disable CoA or Disconnect only when a
change window or vendor certification scope requires it.

## API

```text
GET  /api/v1/system/dac-client
POST /api/v1/system/dac-client/preview
POST /api/v1/system/dac-client/send
GET  /api/v1/system/dac-client/history
```

Read-only admins can inspect status and history. `ops_admin` and `super_admin`
can preview and send requests. Send requests require `confirm: true` when
confirmation policy is enabled.

Example preview:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "coa",
    "target_address": "192.0.2.10",
    "acct_session_id": "acct-123",
    "filter_id": "employee",
    "vlan": 20
  }' \
  http://127.0.0.1:8083/api/v1/system/dac-client/preview | jq .
```

Example confirmed send:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "disconnect",
    "target_address": "192.0.2.10",
    "acct_session_id": "acct-123",
    "correlation_id": "change-ticket-123",
    "confirm": true
  }' \
  http://127.0.0.1:8083/api/v1/system/dac-client/send | jq .
```

## Packet Processing

The client resolves the target in this order:

1. Managed RADIUS client match by target address, NAS-IP-Address, shortname, or
   NAS-Identifier.
2. Session hint lookup from local session history when `session_id` is supplied.
3. Direct request address or NAS identifier when known-client gating is disabled.

Every sent packet is encoded with the resolved shared secret and a
Message-Authenticator. ACK, NAK, unexpected response code, nil response, and
transport error outcomes are persisted. NAK packets preserve `Error-Cause` and
`Reply-Message` when present.

## Data Model

Schema v47 adds:

- `radius_outbound_dac_requests`
- `radius_outbound_dac_attempts`

History stores request identifiers, action, status, target, response code,
Error-Cause, latency, fingerprints, and correlation. User name, calling station,
Class, and State values are hashed/redacted in persisted attribute history.

## Operations

Before a change:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/dac-client | jq '.report.status, .report.policy'
```

After a change:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/dac-client/history?limit=25' | jq '.summary, .records'
```

Investigate any `nak`, `error`, or `blocked` entry before claiming the change
window is complete. Support bundles include `api/dac-client.json` and
`api/dac-client-history.json`.

## Testing

Automated software coverage includes:

- config default and validation tests
- schema v47 migration and retention tests
- redacted history tests
- packet construction tests for CoA and Disconnect
- ACK, NAK with Error-Cause, and transport error tests
- unsupported vendor dynamic action rejection
- admin API, RBAC, OpenAPI, readiness, and support bundle tests
- admin UI build coverage

External device, packet-capture, HA, performance, soak, security, and customer
acceptance evidence is tracked in
`nas-0042-release-certification-checklist.md`.
