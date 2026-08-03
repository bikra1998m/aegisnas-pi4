# Outbound Dynamic Authorization Client

NAS-0042 added the production software path for sending RFC 5176 Dynamic
Authorization from AegisNAS to managed access devices. NAS-0043 adds durable
queueing, retry, expiry, dead-letter, and idempotency controls. NAS-0044 adds
route-aware proxy delivery, Proxy-State loop protection, and RadSec mTLS
outbound CoA/Disconnect routing through configured upstream home servers.
NAS-0045 adds the vendor dynamic-action compiler that converts neutral action
intent into fail-closed Vendor-Specific Attributes for selected vendor packs.
Operators can preview, send immediately, enqueue, replay, cancel, retry,
inspect history, and collect support evidence without exposing shared secrets or
cleartext identity selectors in API responses or support bundles.

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
- Proxy delivery mode using `radius.upstream.routes`, explicit `proxy_route`,
  originating realm, username suffix, default route fallback, deterministic
  pool selection, route-scoped transport policy, and route-scoped proxy policy.
- UDP proxy CoA/Disconnect to upstream home-server dynamic authorization ports.
- RadSec mTLS proxy CoA/Disconnect to X.509-authenticated upstream home
  servers using RFC 6614 RADIUS over TLS on the Go control path.
- Bounded Proxy-State preservation and AegisNAS loop-marker insertion/reject
  controls for multi-hop reverse DAC routing.
- Route, realm, home-server, hop-count, transport, and Proxy-State evidence in
  immediate history, queue records, and attempt history.
- Vendor dynamic-action compile decisions for Cisco, Aruba, Juniper, Ruckus,
  Fortinet, MikroTik, Huawei, and H3C/Comware compatibility packs.
- Neutral dynamic action intents for `policy-update`, `reauth`, `role`, `vlan`,
  `acl`, `qos`, `quarantine`, `unquarantine`, and `terminate`, rendered into
  supported standard attributes and vendor VSAs.
- Fail-closed validation for unknown actions, ambiguous pack selection, disabled
  packs, wrong packet code, oversized VSA payloads, invalid VLAN/rate values, and
  unsupported vendor action attributes.
- Vendor action status, selected packs, compiled attributes, warnings, and
  blockers in preview, send, queue, history, readiness, and support bundles.

Deferred roadmap scope:

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
    outbound_proxy_enabled: true
    outbound_proxy_allow_udp: true
    outbound_proxy_allow_radsec: true
    outbound_proxy_max_hops: 8
    outbound_proxy_loop_marker: aegisnas
    outbound_proxy_add_loop_marker: true
    outbound_proxy_reject_loop_marker: true
    outbound_vendor_actions_enabled: true
    outbound_vendor_actions_require_pack: true
  vendor:
    enabled: true
    compatibility_packs: [standard, cisco, aruba, juniper, ruckus, fortinet, mikrotik, huawei, h3c]
  upstream:
    enabled: true
    transport_policy:
      enabled: true
      mode: enforce
      fail_closed: true
      default_required_transport: any
      allow_mixed_transports: false
    servers:
      - name: upstream-1
        address: 203.0.113.20
        auth_port: 1812
        acct_port: 1813
        dynamic_auth_port: 3799
        secret_ref: env:UPSTREAM_RADIUS_SECRET
        transport: udp
      - name: upstream-radsec
        address: aaa.example.net
        transport: radsec
        radsec:
          port: 2083
          server_name: aaa.example.net
          certificate_file: /etc/aegisnas/radsec/client.crt
          private_key_file: /etc/aegisnas/radsec/client.key
          ca_file: /etc/aegisnas/radsec/ca.crt
          check_crl: true
          tls_min_version: "1.2"
          tls_max_version: "1.3"
          radius_v11: forbid
    routes:
      - name: corp
        enabled: true
        realm: corp.example.test
        match_realms: [corp.example.test]
        default: true
        pool_strategy: fail-over
        status_check: status-server
        servers: [upstream-1]
      - name: secure-corp
        enabled: true
        realm: secure.example.test
        match_realms: [secure.example.test]
        pool_strategy: fail-over
        status_check: status-server
        servers: [upstream-radsec]
```

Production deployments should keep `outbound_require_known_client` and
`outbound_require_confirmation` enabled. Keep `outbound_queue_enabled` and
`outbound_replay_enabled` enabled for production change windows where a transient
NAS timeout should not lose an operator-approved action. Disable CoA or
Disconnect only when a change window or vendor certification scope requires it.
Keep proxy routing enabled for enterprise deployments and make any UDP or
mixed-transport proxy route an explicit transport-policy decision.
Keep `outbound_vendor_actions_enabled` and
`outbound_vendor_actions_require_pack` enabled in production. Explicit pack
selection prevents accidental cross-vendor VSA spray when several compatibility
packs are active.

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

Example proxy preview through a configured upstream route:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "delivery_mode": "proxy",
    "proxy_route": "corp",
    "originating_realm": "corp.example.test",
    "action": "coa",
    "user_name": "alice@corp.example.test",
    "acct_session_id": "acct-123",
    "filter_id": "quarantine",
    "confirm": true
  }' \
  http://127.0.0.1:8083/api/v1/system/dac-client/preview | jq .
```

Example vendor dynamic-action preview:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "coa",
    "target_address": "192.0.2.10",
    "acct_session_id": "acct-123",
    "vendor_action": "acl",
    "vendor_packs": ["cisco", "aruba"],
    "acl_name": "guest-web",
    "policy_tag": "ticket-124"
  }' \
  http://127.0.0.1:8083/api/v1/system/dac-client/preview \
  | jq '.status, .vendor_action_decision'
```

Example queued QoS update for a MikroTik target:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "coa",
    "target_address": "192.0.2.10",
    "acct_session_id": "acct-123",
    "vendor_action": "qos",
    "vendor_packs": ["mikrotik"],
    "download_rate_kbps": 20000,
    "upload_rate_kbps": 5000,
    "idempotency_key": "ticket-125:qos",
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

For direct delivery, the client resolves the target in this order:

1. Managed RADIUS client match by target address, NAS-IP-Address, shortname, or
   NAS-Identifier.
2. Session hint lookup from local session history when `session_id` is supplied.
3. Direct request address or NAS identifier when known-client gating is disabled.

Every sent packet is encoded with the resolved shared secret and a
Message-Authenticator. ACK, NAK, unexpected response code, nil response, and
transport error outcomes are persisted. NAK packets preserve `Error-Cause` and
`Reply-Message` when present.

For proxy delivery, the client resolves the route from explicit `proxy_route`,
`originating_realm`, `proxy_realm`, the `User-Name` suffix, or the default
upstream route. It then selects a home server, applies transport policy and proxy
attribute policy, optionally rewrites `User-Name`, appends bounded `Proxy-State`,
and sends by UDP or RadSec mTLS. RadSec TLS-PSK active sends remain a release
certification item for the FreeRADIUS runtime path; the Go control path supports
X.509 mTLS.

When `vendor_action` is present, the request is first normalized into vendor
intent. The compiler selects the requested `vendor_packs`; when no explicit pack
is supplied it may infer a single supported pack from the resolved target
`nas_type`. If several supported packs are active and the target type is not
specific enough, preview/send/queue are blocked. Compiled attributes are appended
to the normal packet plan and encoded as RADIUS Type 26 VSAs with dictionary
compatible vendor IDs, vendor attribute numbers, and string or integer payload
types. Disconnect-only `terminate` actions require `action: disconnect`; all
other vendor dynamic actions require `action: coa`.

## Data Model

Schema v47 adds:

- `radius_outbound_dac_requests`
- `radius_outbound_dac_attempts`

Schema v48 adds:

- `radius_outbound_dac_queue`
- `radius_outbound_dac_queue_attempts`

Schema v49 adds proxy routing evidence to all four tables:

- `delivery_mode`
- `proxy_route`
- `proxy_realm`
- `proxy_home_server`
- `proxy_hop_count`
- `proxy_state_json`

Schema v50 adds vendor dynamic-action evidence to immediate request and durable
queue records:

- `vendor_action`
- `vendor_packs_json`
- `vendor_compiler_status`
- `vendor_compiler_warnings_json`

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
  http://127.0.0.1:8083/api/v1/system/dac-client \
  | jq '.report.status, .report.policy, .report.proxy_routing, .report.vendor_actions'
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
- proxy route preview, Proxy-State insertion, loop-marker rejection, UDP proxy
  ACK history, and RadSec mTLS CoA ACK tests
- vendor action compiler previews, fail-closed ambiguous pack selection,
  unsupported VSA rejection, Type 26 VSA packet encoding, and history evidence
- admin API, RBAC, OpenAPI, readiness, and support bundle tests
- admin UI build coverage

External device, packet-capture, HA, performance, soak, security, and customer
acceptance evidence is tracked in
`nas-0042-release-certification-checklist.md` and
`nas-0043-release-certification-checklist.md`, and
`nas-0044-release-certification-checklist.md`, and
`nas-0045-release-certification-checklist.md`.
