# Operations Guide

## RadSec

Use [radsec.md](radsec.md) for the RFC 6614 mTLS architecture, certificate
requirements, RADIUS/1.1 capability gating, failure behavior, and deployment
procedure. Run `scripts/radsec-smoke-test.sh` after installing credentials and
before accepting production traffic.

## Service Management

During development, run commands from the repository root.

### Snap Deployments

```bash
snap start aegis-gateway
snap restart aegis-admin-api
snap logs aegis-admin-api -f
snap stop aegis-ai-lite
```

### Package Or VM Deployments

```bash
sudo systemctl restart aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api
sudo systemctl status aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api --no-pager
sudo journalctl -u aegis-admin-api -u aegis-portal -u aegis-session -n 100 --no-pager
```

### Development Commands

```bash
go run ./cmd/aegis-admin migrate --config configs/config.yaml
go run ./cmd/aegis-admin seed --config configs/config.yaml
go run ./cmd/aegis-admin-api run --config configs/config.yaml
```

## Secret Provider Operations

Use [secret-providers.md](secret-providers.md) for the NAS-0007 secret reference
model. Before production sign-off, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/secret-providers | jq '.status, .summary'
```

All required `env:` and `file:` refs must resolve, and inline secret material
must be migrated out of YAML and SQLite. Existing inline secrets remain
backward-compatible during upgrade, but production readiness marks them as
blocking when `security.secrets.production_require_references` is enabled.

## Vendor Mapping Certification Operations

Use [vendor-mapping-certification.md](vendor-mapping-certification.md) for
NAS-0060 software certification of the 141 current partial FreeRADIUS vendor
mappings. Before claiming the software release is ready for external validation,
run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-mapping-certification | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/vendor-mapping-certification/record | jq '.event_id, .status'
```

External hardware, controller, FreeRADIUS production Linux, HA, performance,
soak, security, and customer acceptance proof stays in
[nas-0060-release-certification-checklist.md](nas-0060-release-certification-checklist.md).

## Cisco Family Pack Operations

Use [cisco-family-pack.md](cisco-family-pack.md) for NAS-0061 software
certification of the 922 Cisco-family rows from the pinned FreeRADIUS 3.2.8
registry. Before claiming the software release is ready for external
validation, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/cisco-family-pack | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/cisco-family-pack/record | jq '.event_id, .status'
```

External Cisco IOS/IOS-XE, WLC/Airespace, ASA/VPN, Starent, Meraki,
FreeRADIUS production Linux, HA, performance, soak, security, and customer
acceptance proof stays in
[nas-0061-release-certification-checklist.md](nas-0061-release-certification-checklist.md).

## Aruba/HPE Family Pack Operations

Use [aruba-family-pack.md](aruba-family-pack.md) for NAS-0062 software
certification of the 125 Aruba, HP/ArubaOS-Switch, Aerohive/Extreme, and
Colubris/MSM rows from the pinned FreeRADIUS 3.2.8 registry. Before claiming
the software release is ready for external validation, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/aruba-family-pack | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/aruba-family-pack/record | jq '.event_id, .status'
```

External ArubaOS, Aruba Central, ClearPass, ArubaOS-Switch, Aerohive/Extreme,
Colubris/MSM, FreeRADIUS production Linux, HA, performance, soak, security,
and customer acceptance proof stays in
[nas-0062-release-certification-checklist.md](nas-0062-release-certification-checklist.md).

## Ruckus/ICX Pack Operations

Use [ruckus-icx-pack.md](ruckus-icx-pack.md) for NAS-0064 software
certification of the 97 Ruckus and Foundry rows from the pinned FreeRADIUS 3.2.8
registry. Before claiming the software release is ready for external
validation, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/ruckus-icx-pack | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/ruckus-icx-pack/record | jq '.event_id, .status'
```

External Ruckus SmartZone, ZoneDirector, Unleashed, Ruckus One, ICX/FastIron,
FreeRADIUS production Linux, HA, performance, soak, security, and customer
acceptance proof stays in
[nas-0064-release-certification-checklist.md](nas-0064-release-certification-checklist.md).

## Fortinet/Palo Alto Pack Operations

Use [fortinet-paloalto-pack.md](fortinet-paloalto-pack.md) for NAS-0065
software certification of the 42 Fortinet and PaloAlto rows from the pinned
FreeRADIUS 3.2.8 registry. Before claiming the software release is ready for
external validation, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/fortinet-paloalto-pack | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/fortinet-paloalto-pack/record | jq '.event_id, .status'
```

External Fortinet appliances/controllers, PAN-OS, GlobalProtect, Panorama,
FreeRADIUS production Linux, HA, performance, soak, security, and customer
acceptance proof stays in
[nas-0065-release-certification-checklist.md](nas-0065-release-certification-checklist.md).

## Meraki/UniFi/OpenWiFi Cloud Pack Operations

Use [cloud-controller-pack.md](cloud-controller-pack.md) for NAS-0066 software
certification of the 4 Meraki rows and 1 OpenWiFi row from the pinned
FreeRADIUS 3.2.8 registry plus the 2 AegisNAS-runtime UBNT rate rows used by
UniFi deployments. Before claiming the software release is ready for external
validation, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/cloud-controller-pack | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/cloud-controller-pack/record | jq '.event_id, .status'
```

External Meraki Dashboard, UniFi Network, OpenWiFi OWGW/uCentral, access point,
gateway, switch, appliance, FreeRADIUS production Linux, HA, performance, soak,
security, and customer acceptance proof stays in
[nas-0066-release-certification-checklist.md](nas-0066-release-certification-checklist.md).

## Cambium/TP-Link/D-Link Access Pack Operations

Use [access-vendor-pack.md](access-vendor-pack.md) for NAS-0067 software
certification of all 49 Cambium, TPLink, and Dlink rows from the pinned
FreeRADIUS 3.2.8 registry. Before claiming the software release is ready for
external validation, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/access-vendor-pack | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/access-vendor-pack/record | jq '.event_id, .status'
```

External Cambium cnMaestro/ePMP/PMP, TP-Link Omada, D-Link/Nuclias, access
point, gateway, switch, FreeRADIUS production Linux, HA, performance, soak,
security, and customer acceptance proof stays in
[nas-0067-release-certification-checklist.md](nas-0067-release-certification-checklist.md).

## Huawei/H3C/ZTE Broadband Pack Operations

Use [broadband-vendor-pack.md](broadband-vendor-pack.md) for NAS-0068 software
certification of all 308 Huawei, H3C, and ZTE rows from the pinned FreeRADIUS
3.2.8 registry. Before claiming the software release is ready for external
validation, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/broadband-vendor-pack | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/broadband-vendor-pack/record | jq '.event_id, .status'
```

External Huawei MA/NE/CloudEngine/WLAN/iMaster, H3C Comware/iMC/BRAS/BNG, ZTE
ZX/BNG/PPPoE, FreeRADIUS production Linux, HA, performance, soak, security, and
customer acceptance proof stays in
[nas-0068-release-certification-checklist.md](nas-0068-release-certification-checklist.md).

## Nokia/Alcatel-Lucent Service Router Pack Operations

Use [nokia-alu-service-router-pack.md](nokia-alu-service-router-pack.md) for
NAS-0069 software certification of all 334 Nokia, Alcatel, Alcatel-ESAM,
Alcatel-Lucent-Service-Router, and ALU-AAA rows from the pinned FreeRADIUS
3.2.8 registry. Before claiming the software release is ready for external
validation, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/nokia-alu-pack | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/nokia-alu-pack/record | jq '.event_id, .status'
```

Run the feature gate locally or in CI with:

```bash
make test-nokia-alu-pack
```

External Nokia SR OS, Alcatel AAT, Alcatel ESAM, ALU-AAA, FreeRADIUS
production Linux, HA, performance, soak, security, and customer acceptance
proof stays in
[nas-0069-release-certification-checklist.md](nas-0069-release-certification-checklist.md).

## MikroTik RouterOS Pack Operations

Use [mikrotik-routeros-pack.md](mikrotik-routeros-pack.md) for NAS-0070
software certification of all 32 MikroTik rows from the pinned FreeRADIUS 3.2.8
registry. Before claiming the software release is ready for external
validation, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/mikrotik-pack | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/mikrotik-pack/record | jq '.event_id, .status'
```

Run the feature gate locally or in CI with:

```bash
make test-mikrotik-pack
```

External RouterOS, CAPsMAN, PPP/PPPoE, hotspot, FreeRADIUS production Linux,
CoA/Disconnect, HA, performance, soak, security, and customer acceptance proof
stays in
[nas-0070-release-certification-checklist.md](nas-0070-release-certification-checklist.md).

## Enterprise Switching Pack Operations

Use [switching-vendor-pack.md](switching-vendor-pack.md) for NAS-0071 software
certification of all 69 pinned 3Com, Dell EMC, EqualLogic, Brocade, Force10,
Foundry, Arista, and Extreme rows from the pinned FreeRADIUS 3.2.8 registry.
Before claiming the software release is ready for external validation, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/switching-vendor-pack | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/switching-vendor-pack/record | jq '.event_id, .status'
```

Run the feature gate locally or in CI with:

```bash
make test-switching-vendor-pack
```

External switch firmware, controller APIs, FreeRADIUS production Linux,
CoA/Disconnect, HA, performance, soak, security, and customer acceptance proof
stays in
[nas-0071-release-certification-checklist.md](nas-0071-release-certification-checklist.md).

## Long-Tail Namespace Operations

Use [long-tail-namespace-program.md](long-tail-namespace-program.md) for
NAS-0072 software certification of all 1,126 pinned rows across 92 remaining
in-corpus FreeRADIUS vendor namespaces. Before claiming the software release is
ready for external validation, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/long-tail-namespaces | jq '.report.summary'
```

After automated tests pass, record the current fingerprint:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/long-tail-namespaces/record | jq '.event_id, .status'
```

Run the feature gate locally or in CI with:

```bash
make test-long-tail-namespace
```

External long-tail hardware, controllers, FreeRADIUS production Linux,
CoA/Disconnect, HA, performance, soak, security, compliance, and customer
acceptance proof stays in
[nas-0072-release-certification-checklist.md](nas-0072-release-certification-checklist.md).

## PostgreSQL Data-Plane Operations

Use [postgresql-data-plane.md](postgresql-data-plane.md) for NAS-0008
configuration, migration, FreeRADIUS SQL, and backup notes. Before enterprise
production sign-off, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/database | jq '.status, .active, .warnings'
```

Production deployments should use `database.backend: postgres`,
`database.dsn_ref`, and TLS `sslmode: verify-full` or `verify-ca`. SQLite remains
valid for lite/lab deployments but is reported as degraded for enterprise
readiness.

## FreeRADIUS SQL Accounting Operations

Use [freeradius-sql-accounting.md](freeradius-sql-accounting.md) for NAS-0035
schema, reconciliation, retention, and API details. Before production sign-off,
run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/sql-accounting | jq '.report.status, .report.summary'
```

Run manual reconciliation after importing FreeRADIUS SQL accounting rows or
after a controlled recovery drill:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch_size":500}' \
  http://127.0.0.1:8083/api/v1/system/sql-accounting/reconcile | jq '.status, .result'
```

Production readiness blocks when SQL accounting is disabled, reconciliation is
disabled, the database is unavailable, or stale/error rows remain.

## Accounting Ingest Spool Operations

Use [accounting-ingest-spool-replay.md](accounting-ingest-spool-replay.md) for
NAS-0040 durable local accounting ingest, write-ahead persistence, replay,
poison records, and loss-SLO behavior. Before production sign-off, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-ingest-spool | jq '.report.status, .report.summary'
```

Run bounded replay after database outage drills, service restarts, failover
drills, or packet replay tests:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch_size":500}' \
  http://127.0.0.1:8083/api/v1/system/accounting-ingest-spool/replay | jq '.status, .applied, .failed, .poisoned'
```

Investigate poison records before closing an incident:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/accounting-ingest-spool?status=poison&limit=100' | jq '.records'
```

Production readiness blocks when local accounting ingest spooling or replay is
disabled. Poison, expired, loss-SLO breach, or high queue-utilization evidence
degrades readiness. Support bundles include
`api/accounting-ingest-spool.json`; external packet captures, hardware drills,
HA failover, performance, soak, and security validation are tracked in
`nas-0040-release-certification-checklist.md`.

## Outbound Dynamic Authorization Operations

Use [outbound-dac-client.md](outbound-dac-client.md) for NAS-0042/NAS-0047 RFC
5176 CoA and Disconnect preview/send/queue/replay behavior, proxy/RadSec
routing, vendor dynamic-action compilation, NAS capability/session ownership,
HA-aware cluster handoff, supported vendor-neutral attributes, history, and
troubleshooting.
Before production sign-off, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/dac-client \
  | jq '.report.status, .report.summary, .report.queue_summary, .report.proxy_routing, .report.vendor_actions, .report.nas_ownership, .report.handoff'
```

Review the ownership registry directly when session-scoped changes depend on
the owning NAS:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/nas-ownership \
  | jq '.report.status, .report.summary, .report.session_owners'
```

Review HA handoff authority directly before running CoA from an active/standby
pair:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/dac-handoff \
  | jq '.report.status, .report.decision, .report.summary'
```

Preview before sending:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"coa","target_address":"192.0.2.10","acct_session_id":"acct-123","filter_id":"employee"}' \
  http://127.0.0.1:8083/api/v1/system/dac-client/preview | jq .
```

Queue a confirmed action when retry should survive restart or transient target
loss:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"coa","target_address":"192.0.2.10","acct_session_id":"acct-123","filter_id":"quarantine","idempotency_key":"ticket-123:quarantine","confirm":true}' \
  http://127.0.0.1:8083/api/v1/system/dac-client/enqueue | jq .
```

Preview vendor-specific action compilation before applying vendor roles, ACLs,
QoS, quarantine, or reauth:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"coa","target_address":"192.0.2.10","acct_session_id":"acct-123","vendor_action":"acl","vendor_packs":["cisco"],"acl_name":"guest-web"}' \
  http://127.0.0.1:8083/api/v1/system/dac-client/preview \
  | jq '.status, .vendor_action_decision'
```

Audit lossless ACL AST status before enabling rich ACL intent in production:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/acl-ast \
  | jq '.report.status, .report.summary'
```

Normalize an ACL AST without staging a change:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  --data @acl-policy.json \
  http://127.0.0.1:8083/api/v1/system/acl-ast/normalize \
  | jq '.acl_fingerprint, .acl_round_trip, .acl_diagnostics'
```

Audit certified ACL compiler and decompiler coverage:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/acl-compilers \
  | jq '.report.status, .report.summary'
```

Compile ACL intent for selected vendor packs without applying it:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policy_name":"guest-internet","pack_keys":["standard","cisco","mikrotik"],"rules":[{"action":"permit","direction":"in","protocol":"tcp","source":"any","destination":"any","destination_port":"443"}]}' \
  http://127.0.0.1:8083/api/v1/system/acl-compilers/compile \
  | jq '.run.status, .run.results[] | {pack_key,status,lossless,artifact_fingerprint,diagnostics}'
```

Decompile vendor ACL attributes during certification or support review:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pack_key":"cisco","attributes":[{"name":"Cisco-AVPair","value":"ip:inacl#1=permit tcp any any eq 443","quoted":true}]}' \
  http://127.0.0.1:8083/api/v1/system/acl-compilers/decompile \
  | jq '.result.status, .result.rules, .result.profile_references'
```

Review durable compiler evidence:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/acl-compilers/history \
  | jq '.summary, .history[0:10]'
```

Preview local per-session firewall enforcement before changing nftables:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/runtime-firewall/preview \
  | jq '.plan.status, .plan.summary, .plan.diagnostics'
```

Apply the owned runtime firewall ruleset and record a rollback snapshot:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/runtime-firewall/apply \
  | jq '.result.status, .result.snapshot_id, .result.previous_snapshot_id'
```

Rollback to a known snapshot:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_id":"fw-snap-id"}' \
  http://127.0.0.1:8083/api/v1/system/runtime-firewall/rollback \
  | jq '.result.status, .result.restored_snapshot_id'
```

Preview hierarchical QoS scheduling before changing `tc` state:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/qos-scheduler/preview \
  | jq '.plan.status, .plan.summary, .plan.diagnostics'
```

Compile vendor-safe rate attributes before applying a bandwidth policy:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pack_keys":["mikrotik","wispr","ubnt","huawei","h3c","tplink","zte"],"download_rate_kbps":50000,"upload_rate_kbps":20000}' \
  http://127.0.0.1:8083/api/v1/system/rate-compiler/compile \
  | jq '.event_id, .result.status, .result.attributes'
```

Decompile observed vendor values during a drift or support review:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pack_key":"ubnt","attributes":[{"name":"UBNT-Data-Rate-DL","value":"50000000"},{"name":"UBNT-Data-Rate-UL","value":"20000000"}]}' \
  http://127.0.0.1:8083/api/v1/system/rate-compiler/decompile \
  | jq '.event_id, .result.intent'
```

For dual-stack shaping, confirm the QoS preview includes IPv6 session counts
and `flower` filters before applying:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/qos-scheduler/preview \
  | jq '.plan.summary.ipv6_sessions, .plan.commands[] | select(test("protocol ipv6|flower"))'
```

Preview dynamic VLAN bridge, subinterface, and hostapd VLAN file changes before
changing host network state:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/vlan-lifecycle/preview \
  | jq '.plan.status, .plan.summary, .plan.diagnostics'
```

Apply the owned VLAN lifecycle after a clean preview:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operation":"apply"}' \
  http://127.0.0.1:8083/api/v1/system/vlan-lifecycle/apply \
  | jq '.result.status, .result.snapshot_id, .result.previous_snapshot_id'
```

Rollback a VLAN lifecycle snapshot:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_id":"vlan-snap-id"}' \
  http://127.0.0.1:8083/api/v1/system/vlan-lifecycle/rollback \
  | jq '.result.status, .result.restored_snapshot_id'
```

Use `/api/v1/system/vlan-lifecycle/history` and the support bundle files
`api/vlan-lifecycle.json` and `api/vlan-lifecycle-history.json` during bridge,
VLAN, hostapd, CoA VLAN-change, or rollback investigations.

Compile tagged voice/data VLAN, QinQ, pool, fallback, and auth-fail intent
before changing role policy:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"voice-device","calling_station_id":"aa:bb:cc:dd:ee:ff","nas_identifier":"branch-ap-01","pack_keys":["standard","aegisnas","hp","extreme"]}' \
  http://127.0.0.1:8083/api/v1/system/vlan-policy/compile \
  | jq '.event_id, .result.status, .result.decision, .result.attributes'
```

Preview auth-fail or fallback behavior without changing live state:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"voice-device","auth_failed":true}' \
  http://127.0.0.1:8083/api/v1/system/vlan-policy/preview \
  | jq '.result.status, .result.decision.assignment_mode, .result.diagnostics'
```

Decompile observed packet attributes during a vendor smoke test or support
case:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pack_key":"aegisnas","attributes":[{"name":"AegisNAS-Data-VLAN","value":"21"},{"name":"AegisNAS-Voice-VLAN","value":"30"}]}' \
  http://127.0.0.1:8083/api/v1/system/vlan-policy/decompile \
  | jq '.event_id, .result.decision'
```

Use `/api/v1/system/vlan-policy`, `/api/v1/system/vlan-policy/history`, and
the support bundle files `api/vlan-policy.json` and
`api/vlan-policy-history.json` during tagged VLAN, QinQ, pool, fallback, and
auth-fail investigations. Local Linux bridge and hostapd changes are still
owned by the VLAN lifecycle API; the VLAN policy compiler owns RADIUS reply
semantics and evidence.

Compile route and VRF intent for a routed subscriber or branch role:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"branch-vpn","session_id":"session-1","acct_session_id":"acct-1","pack_keys":["standard","aegisnas","cisco"]}' \
  http://127.0.0.1:8083/api/v1/system/route-policy/compile \
  | jq '.event_id, .result.status, .result.decision.vrf, .result.attributes'
```

Preview a route withdrawal without changing active ownership:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"branch-vpn","lifecycle_action":"accounting-stop","pack_keys":["aegisnas","cisco"]}' \
  http://127.0.0.1:8083/api/v1/system/route-policy/preview \
  | jq '.result.decision.withdraw, .result.attributes'
```

Use `/api/v1/system/route-policy`, `/api/v1/system/route-policy/history`, and
the support bundle files `api/route-policy.json` and
`api/route-policy-history.json` during per-session route, VRF, route-owner,
CoA update, and Accounting Stop withdrawal investigations. Preview and
decompile are evidence-only. Compile updates the software ownership ledger, and
accounting Stop or Accounting-Off withdraws matching active route ownership
rows.

Create an aggregate scheduler override for an existing bandwidth profile:

```bash
curl -fsS -X PUT -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"scheduler":"htb","priority":1,"download_ceil_rate_kbps":30000,"upload_ceil_rate_kbps":10000,"burst_kb":256,"cburst_kb":256}' \
  http://127.0.0.1:8083/api/v1/system/qos-scheduler/profiles/voice
```

Apply the compiled QoS scheduler plan and record a rollback snapshot:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8083/api/v1/system/qos-scheduler/apply \
  | jq '.result.status, .result.snapshot_id, .result.previous_snapshot_id'
```

Rollback QoS scheduling to a known snapshot:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_id":"qos-snap-id"}' \
  http://127.0.0.1:8083/api/v1/system/qos-scheduler/rollback \
  | jq '.result.status, .result.restored_snapshot_id'
```

For session-owned changes, also inspect the ownership decision:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"coa","acct_session_id":"acct-123","filter_id":"employee","confirm":true}' \
  http://127.0.0.1:8083/api/v1/system/dac-client/preview \
  | jq '.status, .target, .ownership_decision'
```

Replay due queue records during a recovery drill:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch_size":25}' \
  http://127.0.0.1:8083/api/v1/system/dac-client/replay | jq .
```

Production readiness blocks when outbound DAC is disabled, known-client gating
or send confirmation is disabled, durable queue/replay is disabled, proxy
routing is disabled or has no usable home servers, Proxy-State hop limits are
unsafe, vendor action compilation is disabled, explicit vendor pack selection is
disabled, NAS ownership tables are unavailable, the history or queue tables are
unavailable, no managed NAS clients exist, no capability-backed NAS clients
exist, or no shared secret can be resolved. NAK, error, blocked, poison,
expired, stale ownership, unknown ownership, blocked proxy-route history,
blocked vendor-action history, blocked ownership decisions, and VSA compiler
warnings degrade readiness until investigated. Support bundles include
`api/dac-client.json`, `api/nas-ownership.json`, and
`api/dac-client-history.json`; external device, packet-capture, HA,
performance, soak, and security validation are tracked in
`nas-0042-release-certification-checklist.md`,
`nas-0043-release-certification-checklist.md`,
`nas-0044-release-certification-checklist.md`,
`nas-0045-release-certification-checklist.md`, and
`nas-0046-release-certification-checklist.md`.

## Accounting Ordering Operations

Use [accounting-idempotency-ordering.md](accounting-idempotency-ordering.md) for
NAS-0036 event identity, duplicate suppression, ordered apply, late Stop merge,
and replay details. Before production sign-off, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-ordering | jq '.report.status, .report.summary'
```

Run bounded replay after SQL imports, packet-loss drills, or controlled
failover recovery:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"limit":1000}' \
  http://127.0.0.1:8083/api/v1/system/accounting-ordering/replay | jq '.status, .result'
```

Production readiness blocks when accounting ordering is disabled, replay is
disabled, the ledger table is unavailable, or stale/error events remain.

## Accounting Counter Operations

Use [accounting-counters-gigawords.md](accounting-counters-gigawords.md) for
NAS-0037 64-bit counter, gigaword rollover, reset detection, and overflow
details. Before production sign-off, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-counters | jq '.report.status, .report.summary'
```

After SQL reconciliation, replay, NAS reboot drills, or large transfer tests,
confirm `counter_error_rows` is zero, expected rollover events are present, and
any reset evidence has a known operational cause.

Production readiness blocks when 64-bit counters are disabled, gigawords are
disabled, reset detection is disabled, max counter width is not 64 bits, or
overflow/error rows remain.

NAS-0038 IPv6, delegated-prefix, and route accounting details are exposed at:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-ip | jq '.report.status, .report.summary'
```

After SQL reconciliation, accounting replay, dual-stack AP tests, or BNG/BRAS
route tests, confirm `invalid_rows` is zero, expected IPv6 address or prefix
rows are present, delegated prefixes are visible for subscriber sessions, and
Stop or Accounting-Off drills close active assignment rows. Support bundles
include `api/accounting-ip.json`; external packet captures and hardware drills
are tracked in `nas-0038-release-certification-checklist.md`.

## Multi-Service Accounting Operations

Use [accounting-multi-service-correlation.md](accounting-multi-service-correlation.md)
for NAS-0039 parent/child session correlation, service-leg evidence,
subscriber service-chain linkage, and conflict handling. Before production
sign-off, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-services | jq '.report.status, .report.summary'
```

During BNG, mobile, voice, VPN, or multi-link PPP investigations, filter recent
evidence by parent session or conflict state:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/accounting-services?parent_session_key=sess-1&limit=100' | jq '.records'

curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/accounting-services?status=conflict&limit=100' | jq '.records'
```

Production readiness blocks when multi-service correlation is disabled or when
Class, Acct-Multi-Session-Id, or subscriber service-chain correlation sources
are disabled. Conflict rows degrade readiness and should be resolved before
production claims. Support bundles include `api/accounting-services.json`;
external packet captures and hardware drills are tracked in
`nas-0039-release-certification-checklist.md`.

## Accounting Charging Operations

Use
[accounting-charging-rating-export.md](accounting-charging-rating-export.md) for
NAS-0041 CDR projection, deterministic rating, retention, export integrity, and
hash-chain behavior. Before production sign-off, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-charging | jq '.report.status, .report.summary'
```

Run bounded reconciliation after SQL imports, ingest-spool replay, failover
drills, or packet-capture replay:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch_size":1000}' \
  http://127.0.0.1:8083/api/v1/system/accounting-charging/reconcile | jq '.status, .result, .summary'
```

Export pending closed and rated CDRs for billing or mediation handoff:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format":"jsonl","limit":5000}' \
  http://127.0.0.1:8083/api/v1/system/accounting-charging/export | jq '.export_id, .record_count, .payload_sha256, .manifest_sha256'
```

Download an export payload when downstream systems need the batch body:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  'http://127.0.0.1:8083/api/v1/system/accounting-charging/export/download?export_id=<export-id>' \
  -o aegisnas-cdr-export.jsonl
```

Production readiness blocks when charging, rating, or export is disabled.
Rating errors and integrity mismatches degrade readiness and should be resolved
before billing claims. Support bundles include `api/accounting-charging.json`;
external billing mediation, packet captures, hardware drills, HA failover,
performance, soak, and security validation are tracked in
`nas-0041-release-certification-checklist.md`.

## Admin Access Workflow

Operators can now sign in with either:

- an admin API token
- admin SSO through OIDC or SAML

Keep token login available as break-glass access even when SSO is enabled.

The normal workflow is:

1. Sign in with SSO or a bootstrap/admin token.
2. Edit objects from the relevant page.
3. Each create, edit, or delete is staged first.
4. Use the pending changes bar to validate.
5. Apply staged changes when validation passes.
6. Use `Revisions` to roll back a bad apply.

Current operator pages in the UI:

- Dashboard
- Access Settings
- Admin Access
- VLANs
- Portal Profiles
- Users
- Devices
- Guest Requests
- Vouchers
- Roles
- Bandwidth
- Policies
- Identity Sources
- RADIUS Clients
- Sessions
- Alerts
- Revisions
- Backups
- AI Insights

Role visibility is now enforced in the UI for:

- `super_admin`
- `ops_admin`
- `guest_admin`
- `read_only`

## Tenant Isolation Operations

Use [tenant-isolation-delegation.md](tenant-isolation-delegation.md) for the
NAS-0034 architecture and API details. Before enabling
`governance.isolation_mode: enforce`, create active tenant profiles, bind
tenant-owned resources, and run monitor-mode evaluations:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/tenant-isolation | jq '.status, .summary, .checks'
```

Production operations should keep `fail_closed`, policy-set ownership, resource
ownership, and resource audit enabled. Support bundles include
`api/tenant-isolation.json`; use that artifact when investigating delegated
admin scope, policy activation, rollback, or missing resource binding issues.

## Runtime Monitoring

Health endpoints are registered by each daemon. In a package-based deployment, the common checks are:

```bash
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8081/health
curl -fsS http://127.0.0.1:8082/health
curl -fsS http://127.0.0.1:8083/health
curl -fsS http://127.0.0.1:8085/health
curl -fsS http://127.0.0.1:8087/health
```

The dashboard is now the primary operator surface for:

- service health
- deployment profile and capability state
- upstream AAA status
- runtime shaping state
- admin SSO runtime state
- SIEM export runtime state
- controller automation runtime state

Telemetry also generates alerts into the `alerts` table. Alerts can be acknowledged from the admin UI.

The AI engine stores recommendations in `ai_recommendations`. These remain advisory and never gate authentication, policy enforcement, or traffic admission.

## Guest, Onboarding, And Access Operations

Current day-two operator workflows include:

- approve or reject guest self-registration requests from `Guest Requests`
- review guest lifecycle counts, delivery failures, and recent request trends from `Guest Requests`
- review sponsor backlog, invite failures, and approval timing from `Guest Requests`
- review device inventory and certificate bundles from `Devices`
- review or update delegated-admin mappings from `Admin Access`
- terminate live sessions from `Sessions`
- acknowledge health and integration alerts from `Alerts`

For captive portal and guest workflow investigations, use the focused runbook in [Login And Captive Portal Test Runbook](login-test-runbook.md).

For managed interface, gateway, DNS, DHCP, firewall, and rollback work in `Access Settings`, use the dedicated [Edge Network Operations Guide](edge-network-operations.md).

For active/standby deployment, shared replication, VIP takeover, and HA history, use the dedicated [HA Active/Standby Runbook](ha-active-standby-runbook.md).

For version-aware upgrade rollback package creation, inspection, rehearsal, and offline restore, use the dedicated [Upgrade Rollback Runbook](upgrade-rollback-runbook.md).

For the live admin API contract, OpenAPI download path, and role-hint guidance, use [Admin API Guide](admin-api.md).

For one-shot cross-domain operational snapshots that combine network, HA, upgrade, and integration state, use the diagnostics report from `Backups` or `GET /api/v1/system/diagnostics-report`.

For recurring redacted troubleshooting bundles without waiting for a manual click during an incident, enable scheduled support bundle exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/support-bundle-exports`.

For recurring report capture without manual operator action, enable scheduled diagnostics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/diagnostics-exports`.

For durable controller, MDM sync, and posture automation history, use `Backups` or `GET /api/v1/system/integration-history`.

For recurring integration capture without manual export timing, enable scheduled integration exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/integration-exports`.

For a durable upstream AAA probe timeline beyond the live dashboard badge, use `Backups` or `GET /api/v1/system/upstream-aaa-history`.

For a durable record of operator-visible admin actions, exports, guest approvals, network changes, HA activations, and upgrade work, use `Backups` or `GET /api/v1/system/audit-history`.

For recurring audit capture without relying on manual export timing, enable scheduled audit exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/audit-exports`.

For guest lifecycle summary, delivery-state visibility, and JSON or CSV handoff artifacts without leaving the approval console, use `Guest Requests` or `GET /api/v1/system/guest-lifecycle`.

For sponsor-approval backlog, invite-delivery failures, and approval-to-completion timing without leaving the guest workflow page, use `Guest Requests` or `GET /api/v1/system/guest-delivery-analytics`.

For top rejection reasons, sponsor versus non-sponsor rejection mix, and submit-to-rejection timing without scanning the raw request list, use `Guest Requests` or `GET /api/v1/system/guest-rejection-analytics`.

For recurring rejection snapshots without relying on a live guest analytics pull, enable scheduled guest rejection analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-rejection-analytics-exports`.

For funnel reach, submit-to-approval / invite / completion timing, and the biggest drop-off points between approval, invite delivery, and successful onboarding, use `Guest Requests` or `GET /api/v1/system/guest-conversion-analytics`.

For recurring funnel snapshots without relying on a live guest analytics pull, enable scheduled guest conversion analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-conversion-analytics-exports`.

For queued, sent, and failed invite throughput plus approval-to-invite and invite-to-completion timing without leaving the guest workflow page, use `Guest Requests` or `GET /api/v1/system/guest-invite-analytics`.

For recurring invite-throughput snapshots without relying on a live guest analytics pull, enable scheduled guest invite analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-invite-analytics-exports`.

For sponsor-by-sponsor backlog aging, slow approval response hotspots, and pending approvals that have been waiting for 30 minutes, 4 hours, or 24 hours, use `Guest Requests` or `GET /api/v1/system/guest-sponsor-analytics`.

For recurring guest delivery analytics snapshots without depending on a manual export step, enable scheduled guest delivery analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-delivery-analytics-exports`.

For top approval or invite error reasons, queued-invite age, and sponsor or company delivery hotspots, use `Guest Requests` or `GET /api/v1/system/guest-delivery-failures`.

For recurring guest delivery failure hotspot snapshots without relying on a live analytics pull during an incident, enable scheduled guest delivery failure exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-delivery-failures-exports`.

For recurring sponsor backlog and approval-response snapshots without relying on a live analytics pull, enable scheduled guest sponsor analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-sponsor-analytics-exports`.

For recurring guest lifecycle capture without depending on a manual export step, enable scheduled guest lifecycle exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/guest-lifecycle-exports`.

For durable session and accounting history beyond the live sessions table, use `Backups` or `GET /api/v1/system/session-history`.

For started/ended trends, auth mix, role mix, VLAN mix, and peak concurrency across a selected window, use `Sessions` or `GET /api/v1/system/session-analytics`.

For recurring session/accounting capture without relying on a manual export step, enable scheduled session exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/session-exports`.

For recurring session trend snapshots without manually exporting analytics every time, enable scheduled session analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/session-analytics-exports`.

For voucher utilization, expiry pressure, and remaining-use visibility without scanning raw voucher codes by hand, use `Vouchers` or `GET /api/v1/system/voucher-analytics`.

For stale voucher inventory, unused stock backlog, and age-band pressure without manually reviewing raw voucher timestamps, use `Vouchers` or `GET /api/v1/system/voucher-aging-analytics`.

For voucher redemption behavior, first-use delay, repeat-use patterns, and voucher-session traffic without manually correlating vouchers against raw accounting rows, use `Vouchers` or `GET /api/v1/system/voucher-redemption-analytics`.

For upcoming voucher expiry pressure, unused vouchers at risk, and remaining finite-use capacity that will age out inside a selected horizon, use `Vouchers` or `GET /api/v1/system/voucher-expiry-analytics`.

For recurring voucher inventory, utilization, and expiry snapshots without relying on a manual export step, enable scheduled voucher analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/voucher-analytics-exports`.

For recurring stale voucher stock snapshots without manually exporting unused aging and trapped remaining-use data every time, enable scheduled voucher aging analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/voucher-aging-analytics-exports`.

For recurring voucher redemption behavior snapshots without manually exporting first-use delay and repeat-use trends each time, enable scheduled voucher redemption analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/voucher-redemption-analytics-exports`.

For recurring voucher expiry horizon snapshots without manually exporting at-risk unused inventory and remaining use capacity each time, enable scheduled voucher expiry analytics exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/voucher-expiry-analytics-exports`.

For recurring HA capture without manual export timing, enable scheduled HA exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/ha/exports`.

For recurring network capture without manual export timing, enable scheduled network exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/network-exports`.

For recurring upstream AAA capture without relying on manual probe-history export timing, enable scheduled upstream AAA exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/upstream-aaa-exports`.

For recurring upgrade-readiness evidence without manually rerunning the rehearsal before every change window, enable scheduled upgrade readiness exports in `Access Settings`, then review artifacts from `Backups` or `GET /api/v1/system/upgrade-readiness-exports`.

## Logs

Logs are structured JSON.

For snap deployments:

```bash
snap logs aegis-admin-api -f
```

For systemd deployments:

```bash
sudo journalctl -u aegis-admin-api -u aegis-portal -u aegis-session -u aegis-radius -u aegis-gateway -f
```

For file logging, paths are set by `logging.output` in the config. File logs rotate at 10 MB, keep five backups, and compress old files.

For appliance login, portal, onboarding, and AAA investigations in Ubuntu VM or package-based deployments, capture a separate-file debug bundle with:

```bash
sudo bash scripts/capture-login-debug-logs.sh --scenario portal-local-failure
```

Recommended scenario names now include:

- `portal-local-postlogin`
- `portal-selfreg-postapprove`
- `portal-voucher-postlogin`
- `device-onboarding-postenroll`
- `admin-sso-callback`
- `controller-sync-warning`

## Integration Operations

When integrations are enabled, operators should verify:

- admin SSO redirect and callback behavior
- SIEM export health and last delivery message
- controller automation last sync message
- MDM or compliance posture synchronization status
- recent integration history for controller, MDM sync, and posture failures or recoveries
- external CA enrollment reachability when `ca_mode: external`

Those states are surfaced in the dashboard and reflected in alerts when delivery or sync degrades.

## Network And Vendor Observability

For edge network operations, use the dashboard or:

```text
/api/v1/system/network-observability
/api/v1/system/vendor-observability
```

Network observability combines apply history, rollback counters, DHCP lease trends, and controller sync health. Vendor observability adds per-vendor auth success and failure counters, VSA parse failures, unsupported attributes, CoA and disconnect outcomes, and a NAS compatibility score. Treat the catalog coverage matrix as the expected capability map, then use the runtime counters to spot mismatched AP profiles, unsupported vendor attributes, broken CoA behavior, or controllers that stopped accepting policy.

For controller changes, preview the operation from the dashboard or `GET /api/v1/system/controller-sync/preview`. Run `pull` first and resolve reported hash drift before a push. A push is locked until the operator enters `PUSH CONTROLLER POLICY`; its result, target adapter, hashes, drift count, applied or failed count, and controller health are written to integration history. Keep scheduled mode at `monitor` or `pull-config` until the selected controller has passed the certification lab against real hardware.

For Aruba Central, verify that `site` names the Classic Central group and `radius_profile` names an existing RADIUS server profile before the first pull. The native adapter manages only WPA2/WPA3 Enterprise WLAN objects. A warning for a personal, open, captive-portal, client-limit, isolation, portal, or bandwidth setting means that field was left untouched in Central and needs a separate controller-side workflow.

For Juniper Mist, use the regional `api.*.mist.com` endpoint and the site UUID, not the display name. Keep the API token and RADIUS shared secret in separate environment variables. Pull first to verify the site and paginated WLAN inventory; then inspect the redacted preview before push. The adapter never deletes WLANs and leaves guest portal, WxLAN policy, inventory, and non-enterprise security modes untouched.

For NAS-0063 Juniper/ERX/Extreme/Mist certification, inspect
`/api/v1/system/juniper-extreme-pack`, record software evidence with
`/api/v1/system/juniper-extreme-pack/record`, and retain support bundle entries
`api/juniper-extreme-pack.json` and `api/juniper-extreme-pack-history.json`.
Treat Mist as Juniper product/controller scope for this pack; the pinned
FreeRADIUS 3.2.8 registry includes Juniper, ERX, and Extreme dictionary rows but
no separate Mist VSA namespace. Execute
[nas-0063-release-certification-checklist.md](nas-0063-release-certification-checklist.md)
before publishing hardware-, firmware-, controller-, or customer-certified
claims.

For NAS-0064 Ruckus/ICX certification, inspect
`/api/v1/system/ruckus-icx-pack`, record software evidence with
`/api/v1/system/ruckus-icx-pack/record`, and retain support bundle entries
`api/ruckus-icx-pack.json` and `api/ruckus-icx-pack-history.json`. Treat
Foundry rows as Ruckus ICX/FastIron product scope for this pack; broader Dell,
Brocade, Arista, Extreme, and 3Com switching claims remain in NAS-0071. Execute
[nas-0064-release-certification-checklist.md](nas-0064-release-certification-checklist.md)
before publishing hardware-, firmware-, controller-, or customer-certified
claims.

For NAS-0065 Fortinet/Palo Alto certification, inspect
`/api/v1/system/fortinet-paloalto-pack`, record software evidence with
`/api/v1/system/fortinet-paloalto-pack/record`, and retain support bundle
entries `api/fortinet-paloalto-pack.json` and
`api/fortinet-paloalto-pack-history.json`. Execute
[nas-0065-release-certification-checklist.md](nas-0065-release-certification-checklist.md)
before publishing hardware-, firmware-, controller-, or customer-certified
claims.

For Ruckus SmartZone, verify API v13_1 availability, the zone UUID, and the existing authentication service name. A pull performs session login, paginated WLAN inventory, per-WLAN detail reads, and logout without mutation. Push creates only standard 802.1X WLANs and uses partial PATCH for existing WLANs. It never deletes WLANs or replaces an entire controller object.

For FortiGate, use a least-privilege REST API administrator restricted to the AegisNAS management source and the target VDOM. Verify the existing RADIUS profile before pull. The native adapter manages only FortiAP enterprise VAP objects and never sends the API token in a query parameter.

For MikroTik, use RouterOS 7.13 or newer with HTTPS REST enabled and a dedicated account. Pull first to inspect managed RADIUS and WiFi profile drift. A push never deletes records and intentionally does not assign profiles to radios or create CAPsMAN provisioning rules. Validate bridge VLAN filtering, radio package compatibility, and provisioning on a lab router before enabling scheduled push. Rotate the RADIUS shared secret through a controlled RouterOS procedure because masked secrets cannot be compared reliably through REST.

For UniFi, generate a scoped API key from the console or Site Manager and point `endpoint` at the official Network integration API base. Use the API site ID, not the legacy site name. Create the RADIUS profile and VLAN networks in UniFi before pull. Push performs full-object updates only after reading current detail, preserving unmanaged optional fields; it never deletes broadcasts, profiles, or networks. Keep scheduled mode read-only until the exact Network release and AP firmware pass the certification lab.

For Cisco Meraki, use `https://api.meraki.com/api/v1` and a least-privilege Dashboard API key with network wireless SSID read/write access. Set `site` to the network ID and create each target SSID name in an available Dashboard slot before pull. Push updates only exact same-name slots and never allocates or renames a slot. Because Dashboard reads omit RADIUS secrets, every confirmed push refreshes the configured secret on matched SSIDs; inspect the redacted preview and archive integration history before rotating it. Keep scheduled mode at `monitor` until the target MR firmware and WPA/VLAN behavior pass the certification lab.

For TIP OpenWiFi, point `endpoint` at the OWGW `/api/v1` base and use a scoped Gateway API key. Set `site` to an AP serial number or venue UUID. Pull first and resolve every missing, ambiguous, invalid-configuration, and VLAN-placement drift item. Push queues whole uCentral documents, but the adapter performs read-modify-write and changes only managed fields inside existing same-name enterprise SSIDs. It never creates an SSID, moves one between interfaces, changes interface VLANs, or overwrites unmanaged radio and service settings. Confirm command completion and convergence with `scripts/openwifi-controller-smoke-test.sh` before enabling scheduled push.

Run `scripts/vendor-certification-lab.sh` for each supported production vendor and archive its `summary.json`, API payloads, RADIUS results, packet capture, controller evidence, and optional upgrade/rollback artifacts. The full procedure and safety gates are in [vendor-certification-lab.md](vendor-certification-lab.md).

## Backup And Restore

Use the CLI for full appliance backup and the admin UI for config-only JSON backup. See [Backup and Restore Procedures](backup-restore.md).

Run at least one restore drill before production sign-off.

Before handing an issue to another team or opening a support case, download:

- the diagnostics report in JSON or CSV
- the audit history export in JSON or CSV when the issue crosses multiple operator actions
- the integration history export in JSON or CSV when the issue is controller- or MDM-related
- the support bundle zip

That gives you a quick human-readable snapshot plus the deeper redacted artifact set.

## Software Updates

Snaps refresh automatically by default. For controlled maintenance windows:

```bash
snap set system refresh.timer=sun,02:00-04:00
```

For VM or package-based deployments from a local clone, pull the updated repo and follow the relevant runbook for rebuild, reinstall, and service restart.

For in-place Ubuntu VM upgrades with migration and network safety checks, use:

```bash
sudo bash scripts/ubuntu-vm-upgrade-smoke-test.sh --wan <wan-if> --lan <lan-if>
```

For version-aware rollback rehearsal before a production change window, use:

```bash
sudo bash scripts/ubuntu-upgrade-rollback-rehearsal.sh
```

Before updating production devices:

1. Export a config JSON backup.
2. Create a full CLI backup.
3. Confirm the management path is reachable.
4. Confirm break-glass admin token access still works before changing SSO settings.
5. Apply the update.
6. Check health, sessions, RADIUS auth, portal login, onboarding, alerts, and dashboard integration state.
7. Review edge-network preview, risk banner, validation result, rollback snapshots, lease history, and apply history if network settings are part of the change.
8. For HA-enabled nodes, run `scripts/ha-active-standby-smoke-test.sh` on both active and standby nodes and review HA history plus replication freshness before failover drills.
9. If standby auto-stage or auto-activation is enabled, confirm the smoke helper summary includes the expected `auto_stage_status` and `auto_activate_status`.
10. Use `scripts/ha-failover-drill.sh` on the active node for a controlled promotion and recovery test with saved artifacts under `/var/tmp/aegisnas-ha-failover/`.
11. When you want confidence over repeated cycles instead of a single drill, run `scripts/ha-soak-test.sh --cycles <n>` on the active node. Multi-cycle runs require `high_availability.preempt: true`.
12. After both HA nodes are upgraded, run `scripts/ha-pair-upgrade-validate.sh` from the active node. Add `--peer-ssh <user@host>` when you want peer schema and service proof, not just peer API status.
13. Create and inspect a fresh upgrade rollback package, then run `scripts/ubuntu-upgrade-rollback-rehearsal.sh` so the rollback path is proven before the real maintenance window.
## Product PEN Operations

Treat a PEN change as a maintenance-window operation. Take a backup, verify HA health, use the Vendor Compatibility preview, update every peer dictionary, apply, verify `/api/v1/system/vendor-identity`, run `freeradius -XC`, and inspect a packet capture. `applying` means an interrupted operation and requires rollback recovery. Never clear migration records manually or extend `legacy_accept_until` without a documented peer dependency. Full procedure: `vendor-identity.md`.

## Attribute Registry Operations

Run `make test-attribute-registry`, `make test-dictionary-release-profiles`, `make test-compatibility-evidence`, `make test-vsa-codec`, and `make test-opaque-passthrough` before packaging or upgrading. Compare `/api/v1/system/dictionary-release-profiles`, `/api/v1/system/compatibility-evidence`, `/api/v1/system/vsa-codec`, `/api/v1/system/opaque-passthrough`, and `/api/v1/system/attribute-registry?limit=1` source hashes across HA nodes and reject mixed hashes or release profile IDs. Upstream dictionary changes require a reviewed generated diff; installed dictionary paths may be scanned for deployment coverage but cannot mutate the embedded packet registry. Full procedure: `attribute-registry.md`, `dictionary-release-profiles.md`, `compatibility-evidence.md`, `vsa-codec.md`, and `opaque-passthrough.md`.

## Address Policy Operations

For dual-stack subscriber or enterprise access roles, configure
`radius.address_policy` before enabling vendor packs that consume framed
addresses, DHCPv6 metadata, router advertisement hints, or delegated prefixes.
Validate pool CIDRs, start/end ranges, DNS values, prefix lengths, and role
references through Access Settings or:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/address-policy | jq '.report.status, .report.summary'
```

Preview a risky change before saving controller or NAS-side configuration:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"branch-dualstack","session_id":"dry-run","pack_keys":["standard","aegisnas","cisco"]}' \
  http://127.0.0.1:8083/api/v1/system/address-policy/preview | jq '.result.status, .result.summary'
```

Use `compile` only when recording active or withdrawn software ownership is
intended. Accounting Stop and Accounting-Off withdraw matching active
assignments when `stop_withdrawal` is enabled. Release claims for native DHCPv6
server behavior, router advertisement packet emission, and device-specific pool
enforcement must be backed by the NAS-0056 release certification checklist.

## Translation Policy Operations

For CGNAT, NAT44, NAT64, DS-Lite, MAP-T, or dual-stack subscriber roles,
configure `radius.translation_policy` before enabling vendor packs that consume
translation AVPairs, NAT pool names, public IPv4 selectors, or deterministic
port-block metadata. Validate public pool CIDRs, start/end ranges, NAT64
prefixes, role references, and port limits through Access Settings or:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/translation-policy | jq '.report.enabled, .report.summary'
```

Preview a risky change before saving controller or NAS-side configuration:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"branch-dualstack","session_id":"dry-run","pack_keys":["aegisnas","cisco","starent"]}' \
  http://127.0.0.1:8083/api/v1/system/translation-policy/preview | jq '.result.status, .result.summary'
```

Use `compile` only when recording active or withdrawn software ownership is
intended. Accounting Stop and Accounting-Off withdraw matching active
translation mappings when `stop_withdrawal` is enabled. Release claims for
native CGNAT/NAT64 dataplane behavior, lawful logging, and device-specific
translation enforcement must be backed by the NAS-0057 release certification
checklist.

## Dynamic Subscriber Route Export Operations

Use the subscriber route export API to publish active route ownership into a
reviewable BGP/OSPF/OSPF3 plan. Live routing apply is off by default; previews
and evidence remain available while `apply_enabled` is false.

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/subscriber-route-export \
  | jq '.report.status, .report.summary, .report.evidence.summary'
```

Preview before enabling live apply:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/subscriber-route-export/preview \
  | jq '.plan.artifact_text, .plan.withdrawals, .plan.diagnostics'
```

Apply only after FRR and routing-domain certification are complete:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/subscriber-route-export/apply \
  | jq '.result.status, .result.snapshot_id, .result.plan.summary'
```

Review `/api/v1/system/subscriber-route-export/history` after every preview,
apply, skipped apply, failed apply, or rollback. Support bundles include
`api/subscriber-route-export.json` and
`api/subscriber-route-export-history.json`. Release claims for FRR convergence,
route reflection, physical FIB installation, HA failover, performance, soak,
and security must be backed by the NAS-0059 release certification checklist.

## Atomic Enforcement Transaction Operations

Use the atomic transaction API for coordinated VLAN, route export, QoS,
firewall, and controller enforcement changes. The coordinator previews each
participant, applies in dependency order, records one ledger entry, checks
drift after apply, and compensates already-applied targets in reverse order
when a later target fails.

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/enforcement-transactions \
  | jq '.report.status, .report.summary, .report.evidence.summary'
```

Run preview before an apply:

```bash
curl -fsS -X POST -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targets":["vlan_lifecycle","subscriber_route_export","runtime_qos","runtime_firewall"]}' \
  http://127.0.0.1:8083/api/v1/system/enforcement-transactions/preview \
  | jq '.result.plan.status, .result.plan.targets'
```

Treat `blocked` as fail-closed. Treat `degraded` as review-required; first
deployment can be degraded when no active snapshots exist. Review
`/api/v1/system/enforcement-transactions/history` after every apply, drift
check, compensation, or rollback. Release claims for physical dataplane,
controller behavior, HA failover, performance, soak, and security must be
backed by the NAS-0058 release certification checklist.
