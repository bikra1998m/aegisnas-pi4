# AAA Product Implementation Notes

This document records the exact implementation sequence used to turn AegisNAS into an external-AAA-capable edge appliance. It is written for future maintenance work so the reasoning does not have to be reconstructed later.

## Goal

Make AegisNAS behave like a productized Network Access Server that:

- proxies RADIUS auth and accounting to upstream AAA servers
- can authenticate captive portal users through that same path
- supports primary and secondary AAA servers with failover
- preserves stable session state locally
- supports reply-attribute mapping
- supports interim accounting
- supports `CoA-Request` and `Disconnect-Request`
- preserves break-glass local access paths

## Implementation Order

### 1. Extend Runtime Configuration

Files:

- [config.go](F:/random_project/Pookie/aegisnas-pi4/internal/config/config.go)
- [config.example.yaml](F:/random_project/Pookie/aegisnas-pi4/configs/config.example.yaml)

Added config fields:

- `radius.nas_identifier`
- `radius.request_timeout_seconds`
- `radius.interim_update_seconds`
- `radius.dynamic_auth.enabled`
- `radius.dynamic_auth.port`
- `portal.radius_auth`
- `portal.local_fallback`

Reason:

- portal auth and session accounting need a shared NAS identity
- CoA and disconnect need an explicit listener
- broker traffic needs deterministic timeout behavior
- product mode needs an explicit switch between local-only portal auth and brokered portal auth

### 2. Expand Session Schema

Files:

- [migrate.go](F:/random_project/Pookie/aegisnas-pi4/internal/db/migrate.go)
- [migrate_test.go](F:/random_project/Pookie/aegisnas-pi4/internal/db/migrate_test.go)

Added session columns:

- `identity_source`
- `filter_id`
- `radius_class`
- `session_timeout`
- `idle_timeout`
- `acct_session_time`
- `called_station_id`
- `nas_identifier`

Reason:

- upstream reply attributes needed a durable home
- per-session timeout enforcement could not rely only on role defaults
- interim accounting required a tracked session duration

### 3. Seed RADIUS Mapping Hints

File:

- [seed.go](F:/random_project/Pookie/aegisnas-pi4/internal/db/seed.go)

Added a seeded, disabled-by-default `identity_sources` row of `type = 'radius'` with example JSON for:

- `filter_id_roles`
- `filter_id_bandwidth_profiles`
- `vlan_roles`

Reason:

- reply-attribute mapping needed a place operators could edit without changing code

### 4. Make The Local FreeRADIUS Broker First-Class

Files:

- [generator.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/generator.go)
- [client.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/client.go)

Changes:

- generator now always ensures localhost broker clients exist with `cfg.Radius.Secret`
- broker client code sends PAP auth and accounting to local FreeRADIUS using the configured shared secret
- broker packet parsing extracts:
  - `Filter-Id`
  - `Class`
  - VLAN
  - session timeout
  - idle timeout
  - vendor bandwidth hints

Reason:

- the portal and session services needed a stable way to use the exact same AAA path as APs and switches

### 5. Add Reply-Attribute Mapping

File:

- [mapping.go](F:/random_project/Pookie/aegisnas-pi4/internal/radius/mapping.go)

Mapping logic order:

1. use enabled radius identity-source JSON mappings
2. allow direct `Filter-Id == role name`
3. allow direct `Filter-Id == bandwidth profile name`
4. allow VLAN-to-role mapping
5. fall back to role defaults
6. let explicit reply timeouts override local defaults

Reason:

- upstream AAA should be able to shape local session policy without hardcoding every upstream vocabulary into the app

### 6. Move Portal Username/Password Auth Through The Broker

Files:

- [auth.go](F:/random_project/Pookie/aegisnas-pi4/internal/portal/auth/auth.go)
- [server.go](F:/random_project/Pookie/aegisnas-pi4/internal/portal/server/server.go)

Behavior:

- local admin auth is tried first as break-glass access
- if `portal.radius_auth` is enabled, the portal authenticates through local FreeRADIUS
- if upstream AAA is unavailable and `portal.local_fallback` is enabled, local and LDAP fallback are allowed
- vouchers stay local

Reason:

- this keeps the product safe in outage conditions without turning local fallback into an accidental bypass of upstream policy

### 7. Persist Real Session Policy

Files:

- [server.go](F:/random_project/Pookie/aegisnas-pi4/internal/portal/server/server.go)
- [statemachine.go](F:/random_project/Pookie/aegisnas-pi4/internal/portal/statemachine.go)

Changes:

- portal sessions now use `uuid` session IDs
- session rows persist:
  - auth method
  - identity source
  - role
  - bandwidth profile
  - `Filter-Id`
  - `Class`
  - timeouts
  - called station ID
  - NAS identifier
- portal memory state now re-checks the DB before treating a client as authenticated

Reason:

- disconnects or timeout enforcement can happen in the session service, so the portal cannot trust only its own memory cache

### 8. Add Interim Accounting And Better Timeout Enforcement

File:

- [manager.go](F:/random_project/Pookie/aegisnas-pi4/internal/sessions/manager.go)

Changes:

- timeout enforcement now honors per-session timeout columns first, then role defaults
- timeout sweeps collect expired sessions first and terminate them after closing the result set to avoid SQLite `SQLITE_BUSY`
- interim accounting now runs on a configurable ticker

Reason:

- upstream AAA systems expect stable session duration and periodic accounting, and SQLite needed a two-phase timeout pass to stay reliable

### 9. Add Dynamic Authorization

Files:

- [dynamic_auth.go](F:/random_project/Pookie/aegisnas-pi4/internal/sessions/dynamic_auth.go)
- [main.go](F:/random_project/Pookie/aegisnas-pi4/cmd/aegis-session/main.go)

Behavior:

- listen on `radius.dynamic_auth.port`
- use upstream home-server secrets for request verification
- handle:
  - `Disconnect-Request`
  - `CoA-Request`
- terminate or reclassify active sessions by:
  - `Acct-Session-Id`
  - username
  - calling-station ID

Reason:

- this is the piece that lets an enterprise AAA platform actively steer the edge appliance after the initial accept

## Validation Steps Used

After implementation:

1. ran `gofmt` on all changed Go files
2. ran `go test ./...`
3. ran `go run ./cmd/aegis-admin validate-config --config configs/config.example.yaml`

The full suite passed after fixing one SQLite locking issue in timeout enforcement.

## Known Deliberate Limits

- storage NAS features are still a separate product layer
- CoA currently updates local session policy state, not device-specific shaping engines
- vendor-neutral ACL rule preview/rendering is present, but reusable ACL policy storage and device smoke testing are still separate work

## Best Next Steps

1. expose upstream AAA health and dynamic-auth activity in the admin UI
2. add live shaping hooks so CoA changes alter forwarding behavior immediately
3. define a clearer outage policy for which local identities are allowed during AAA failure
4. add storage NAS services only after the network-appliance behavior is considered stable
