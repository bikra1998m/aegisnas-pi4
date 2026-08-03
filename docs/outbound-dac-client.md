# Outbound Dynamic Authorization Client

NAS-0042 added the production software path for sending RFC 5176 Dynamic
Authorization from AegisNAS to managed access devices. NAS-0043 adds durable
queueing, retry, expiry, dead-letter, and idempotency controls. Operators can
preview, send immediately, enqueue, replay, cancel, retry, inspect history, and
collect support evidence without exposing shared secrets or cleartext identity
selectors in API responses or support bundles.

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
- Durable outbound queue with hashed idempotency keys, checksum-verified
  payload replay, bounded exponential backoff, maximum attempts, expiry,
  poison/dead-letter state, cancel, manual retry, background replay, queue
  summaries, and redacted queue history.

Deferred roadmap scope:

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
    outbound_queue_enabled: true
    outbound_replay_enabled: true
    outbound_max_queue_records: 10000
    outbound_max_attempts: 6
    outbound_initial_retry_seconds: 5
    outbound_max_retry_seconds: 300
    outbound_record_ttl_seconds: 3600
    outbound_replay_interval_seconds: 15
    outbound_batch_size: 50
    outbound_lock_seconds: 60
    outbound_ack_retention_seconds: 86400
    outbound_dead_letter_retention_seconds: 2592000
    outbound_idempotency_window_seconds: 3600
```

Production deployments should keep `outbound_require_known_client` and
`outbound_require_confirmation` enabled. Keep `outbound_queue_enabled` and
`outbound_replay_enabled` enabled for production change windows where a transient
NAS timeout should not lose an operator-approved action. Disable CoA or
Disconnect only when a change window or vendor certification scope requires it.

## API

```text
GET  /api/v1/system/dac-client
POST /api/v1/system/dac-client/preview
POST /api/v1/system/dac-client/send
POST /api/v1/system/dac-client/enqueue
POST /api/v1/system/dac-client/replay
POST /api/v1/system/dac-client/cancel
POST /api/v1/system/dac-client/retry
GET  /api/v1/system/dac-client/history
```

Read-only admins can inspect status and history. `ops_admin` and `super_admin`
can preview, send, enqueue, replay, cancel, and retry requests. Send and enqueue
requests require `confirm: true` when confirmation policy is enabled.

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

Example durable enqueue with duplicate suppression:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "coa",
    "target_address": "192.0.2.10",
    "acct_session_id": "acct-123",
    "filter_id": "quarantine",
    "correlation_id": "change-ticket-124",
    "idempotency_key": "change-ticket-124:quarantine",
    "confirm": true
  }' \
  http://127.0.0.1:8083/api/v1/system/dac-client/enqueue | jq .
```

Replay due queue records manually:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch_size":25}' \
  http://127.0.0.1:8083/api/v1/system/dac-client/replay | jq .
```

Cancel or retry one queue record:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"queue_id":"dacq-example","reason":"change window closed"}' \
  http://127.0.0.1:8083/api/v1/system/dac-client/cancel | jq .

curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"queue_id":"dacq-example"}' \
  http://127.0.0.1:8083/api/v1/system/dac-client/retry | jq .
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

Schema v48 adds:

- `radius_outbound_dac_queue`
- `radius_outbound_dac_queue_attempts`

History stores request identifiers, action, status, target, response code,
Error-Cause, latency, fingerprints, and correlation. User name, calling station,
Class, and State values are hashed/redacted in persisted attribute history.
Queue records store the replay payload internally with a SHA-256 checksum; API
and support-bundle responses expose only redacted metadata, payload hashes,
idempotency hashes, retry state, and outcome evidence.

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

Investigate any `nak`, `error`, `blocked`, `poison`, or `expired` entry before
claiming the change window is complete. Support bundles include
`api/dac-client.json` and `api/dac-client-history.json`.

## Testing

Automated software coverage includes:

- config default and validation tests
- schema v47 migration and retention tests
- redacted history tests
- packet construction tests for CoA and Disconnect
- ACK, NAK with Error-Cause, and transport error tests
- durable queue enqueue, duplicate suppression, claim, replay, cancel, manual
  retry, retry backoff, expiry, and poison tests
- unsupported vendor dynamic action rejection
- admin API, RBAC, OpenAPI, readiness, and support bundle tests
- admin UI build coverage

External device, packet-capture, HA, performance, soak, security, and customer
acceptance evidence is tracked in
`nas-0042-release-certification-checklist.md` and
`nas-0043-release-certification-checklist.md`.
