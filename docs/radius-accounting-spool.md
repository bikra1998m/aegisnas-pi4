# Durable RADIUS Accounting Spool

Feature ID: NAS-0012

## Purpose

Durable proxy accounting protects RFC 2866 `Accounting-Request` records when the local FreeRADIUS accounting path, upstream home server, network route, or proxy policy is temporarily unavailable. Instead of losing Start, Stop, or Interim-Update records after a send failure, AegisNAS persists the accounting payload, retries it with bounded backoff, records every attempt, and moves exhausted records to a poison state for operator review.

This is required for enterprise AAA because accounting drives billing, audit, subscriber state, usage reporting, session correlation, and incident reconstruction. Vendors and products across Cisco, Juniper, Aruba/HPE, Huawei, MikroTik, Fortinet, Ruckus, Nokia/Alcatel-Lucent, Ericsson, Cambium, Ubiquiti, and ISP/BNG platforms all depend on reliable RFC 2866 accounting and often add VSAs to the same packets.

## Standards And Dictionaries

- RFC 2866: RADIUS Accounting.
- RFC 2865: shared RADIUS packet model and standard attributes used in accounting packets.
- RFC 5080: operational behavior and duplicate/retry considerations.
- RFC 6614: RadSec transport, when proxy paths use TLS-backed home servers.
- FreeRADIUS standard dictionaries and vendor accounting dictionaries: packet payloads may include standard accounting attributes and AegisNAS-rendered vendor accounting attributes.

## Architecture

`radius.SendAccounting` remains the production send path. Packet-construction errors fail fast because replaying malformed local input cannot succeed. Transport errors, timeout errors, and unexpected response codes are converted into durable spool records when `radius.upstream.accounting_spool.enabled` is active.

The spool persists:

- deterministic `record_id` derived from the canonical JSON accounting payload
- route, realm, upstream server metadata
- user, session, and accounting status type
- payload JSON and SHA-256 checksum
- attempt count, maximum attempts, next attempt, expiry, owner node, and lock
- attempt history with result, error, response code, latency, and next retry

The `aegis-radius run` daemon starts a background replay loop. Operators can also trigger an immediate replay from `POST /api/v1/system/accounting-spool/replay`.

## Configuration

```yaml
radius:
  upstream:
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
```

## API

- `GET /api/v1/system/accounting-spool`
- `GET /api/v1/system/accounting-spool?status=queued&limit=100`
- `GET /api/v1/system/accounting-spool?record_id=<record-id>`
- `POST /api/v1/system/accounting-spool/replay`

The read endpoint is available to read-only roles. Replay requires `ops_admin` or `super_admin`.

The same summary appears in:

- `/api/v1/system/status` as `radius.accounting_spool`
- `/api/v1/system/production-readiness` as `radius_accounting_spool`
- the admin dashboard Upstream AAA panel

## Operational States

- `queued`: waiting for the next retry.
- `retrying`: claimed by a node for replay.
- `sent`: replay succeeded and an `Accounting-Response` was received.
- `poison`: max attempts were exhausted or payload integrity failed.
- `expired`: record TTL elapsed before successful replay.

Poison records should be exported or inspected before pruning. They normally indicate a persistent upstream, policy, packet, or credential problem.

## High Availability

Replay claims use `owner_node` and `locked_until` so another node can recover stale work after the lock expires. For full HA, the database backend must be shared or replicated according to the HA runbook. External HA validation is tracked in `nas-0012-release-certification-checklist.md`.

## Software Completion

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes

External certification does not block closure of NAS-0012.
