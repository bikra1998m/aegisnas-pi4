# Controller CWA And Safe Per-session Portal

NAS-0081 implements the software lifecycle for controller captive web
authentication (CWA), safe per-session redirects, RFC 8910 captive portal API
responses, bounded walled-garden intent, and post-auth RFC 5176 CoA handoff.

## What It Solves

CWA deployments often fail because redirect ACLs, portal reachability, session
identity, controller ownership, and post-auth policy changes are configured in
different places. AegisNAS now builds one deterministic plan that shows:

- the RFC 8910 API endpoint and payload served by `aegis-portal`;
- guest SSIDs that use `auth_mode: captive-portal`;
- required and operator-declared walled-garden entries;
- controller redirect policies for Cisco, Aruba, Ruckus, Fortinet, Meraki,
  UniFi, Mist, OpenWiFi, hostapd, and related access vendors;
- post-auth CoA or Disconnect actions guarded by `radius.dynamic_auth`;
- compliance checks, blockers, warnings, evidence history, and runtime status.

## Configuration

Configure the lifecycle under `portal.cwa`.

```yaml
portal:
  enabled: true
  cwa:
    enabled: true
    mode: monitor
    fail_closed: true
    rfc8910_api_enabled: true
    https_required: true
    portal_base_url: "https://portal.example.com"
    captive_api_path: "/captive-portal/api"
    controller_redirect_enabled: true
    per_session_walled_garden: true
    session_binding_required: true
    coa_after_authentication: true
```

Use `mode: monitor` until controller/AP firmware and client OS behavior are
certified. Use `mode: enforce` with `fail_closed: true` only after release
certification evidence exists for the exact environment.

## API

```text
GET  /api/v1/system/cwa-portal-lifecycle
POST /api/v1/system/cwa-portal-lifecycle/preview
POST /api/v1/system/cwa-portal-lifecycle/apply
GET  /api/v1/system/cwa-portal-lifecycle/history
```

The portal service serves RFC 8910 JSON at `/captive-portal/api` or the
configured `portal.cwa.captive_api_path`. The response uses
`application/captive+json` and `Cache-Control: no-store`.

## Operations

1. Enable `portal.enabled`, `portal.cwa.enabled`, and at least one guest SSID
   with `auth_mode: captive-portal`.
2. Set an HTTPS `portal.cwa.portal_base_url` that matches the certificate served
   to clients.
3. Declare any extra pre-auth destinations in `portal.cwa.walled_garden`.
4. Enable `radius.dynamic_auth.enabled` before using post-auth CoA.
5. Preview the lifecycle and resolve blockers.
6. Apply to record evidence and runtime status.
7. Complete `docs/nas-0081-release-certification-checklist.md` before making
   customer claims for a controller/AP family.

## Safety Model

Software completion does not claim live controller mutation. Preview and apply
record intent, evidence, and runtime status. Controller redirect behavior,
DHCP/RA RFC 8910 advertisement, AP firmware redirect behavior, packet captures,
HA, performance, soak, security review, and customer acceptance are release
certification activities.
