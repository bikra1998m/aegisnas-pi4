# TACACS+ Command Authorization

NAS-0033 adds TACACS+ device-administration support for command
authorization, privilege enforcement, and accounting evidence.

## Scope

The software implementation covers:

- RFC 8907 TACACS+ packet header handling and encrypted body processing
- PAP and ASCII local-user authentication
- authorization request parsing for shell command arguments
- command reconstruction from `cmd` and `cmd-arg` AV pairs
- command-set policy with role, privilege, tenant, and vendor constraints
- typed policy-engine gating through `attribute.tacacs.*` fields
- authorization reply rendering with permit, deny, monitor override, and error
  outcomes
- accounting request parsing and durable accounting evidence
- Admin API preview/evaluate and command-set management
- system status, production readiness, OpenAPI, support bundle, UI, and tests

External device certification remains tracked in
`nas-0033-release-certification-checklist.md`.

## Configuration

```yaml
tacacs:
  enabled: true
  listen_address: "0.0.0.0"
  port: 49
  mode: "enforce"
  fail_closed: true
  secret_ref: "env:AEGIS_SECRET_TACACS_SHARED"
  require_known_client: true
  allow_unencrypted: false
  authentication_source: "local"
  clients:
    - name: "core-switch-01"
      address: "192.0.2.10"
      secret_ref: "env:AEGIS_SECRET_TACACS_CORE_SWITCH_01"
      vendor: "cisco"
      tenant: "default"
      enabled: true
  command_sets:
    - name: "ops-show"
      default_action: "deny"
      permit: ["show *", "ping *"]
      deny: ["show running-config", "configure *"]
      roles: ["ops"]
      privilege_levels: [5, 15]
      vendors: ["cisco", "arista"]
```

Use secret references for production. Inline TACACS+ secrets are accepted only
when the global secret policy allows inline material.

## Command Policy

TACACS+ authorization requests carry shell command attributes as AV pairs. The
server builds a normalized command from:

- `cmd=<base-command>`
- repeated `cmd-arg=<argument>`

`cmd-arg=<cr>` is ignored. A command such as `cmd=show`,
`cmd-arg=interfaces`, and `cmd-arg=status` becomes
`show interfaces status`.

Command-set precedence is:

1. disabled sets are ignored
2. role, privilege, vendor, and tenant filters must match
3. matching deny glob rejects the command
4. matching permit glob permits the command
5. the command set default action is applied
6. no matching set means deny

Globs support `*` and `?`. Raw regular expressions are intentionally not used
in the operator-facing command-set path.

## Typed Policy Integration

When the typed policy engine is enabled, TACACS+ requests are also evaluated as
policy requests with:

- `auth_method=tacacs`
- `attribute.protocol=tacacs`
- `attribute.tacacs.command`
- `attribute.tacacs.command_hash`
- `attribute.tacacs.privilege_level`
- `attribute.tacacs.service`
- `attribute.tacacs.port`
- `attribute.tacacs.remote_address`
- `attribute.tacacs.client_known`
- `attribute.tacacs.client_enabled`

If typed policy denies and `tacacs.fail_closed=true`, the command is denied
before command-set matching.

## APIs

- `GET /api/v1/system/tacacs`
- `POST /api/v1/system/tacacs/evaluate`
- `POST /api/v1/system/tacacs/command-sets`
- `PUT /api/v1/system/tacacs/command-sets/{name}`

Read-only administrators can inspect TACACS+ state. Ops and super admins can
evaluate commands and manage command sets.

## Persistence

Schema v38 adds:

- `tacacs_command_sets`
- `tacacs_authorization_events`
- `tacacs_accounting_records`
- `tacacs_protocol_events`

Usernames are stored as hashes in protocol evidence tables. Commands are stored
with both bounded clear text and `command_hash` to support troubleshooting and
privacy-aware search.

## Operations

Use monitor mode for migration and packet capture. In monitor mode, denied
commands are logged as deny decisions but authorization replies are permitted
with a monitor message. Use enforce mode for production.

Production readiness expects:

- `tacacs.enabled=true`
- `tacacs.mode=enforce`
- known clients enabled
- secret references configured
- encrypted packets only
- at least one enabled command set
- audit enabled

