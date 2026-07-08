# Architecture Overview

AegisNAS Pi4 is divided into operational planes so each service has a clear boundary and safe failure mode.

- Gateway: nftables firewall, NAT, VLAN routing, captive redirect hooks, and config rollback.
- AAA: FreeRADIUS configuration generation, PAP, accounting, EAP templates, local users, vouchers, and LDAP-backed identity.
- Portal: guest login, voucher login, status, success, logout, branding, and rate limiting.
- Session: active session tracking, timeouts, concurrent session checks, and admin termination.
- Policy: deterministic role, source, SSID, auth-method, VLAN, timeout, bandwidth, quarantine, and portal-profile decisions.
- Admin API and UI: CRUD, staged changes, validation, apply, rollback, backup/restore, alerts, and AI recommendations.
- AI engine: advisory auth-failure grouping, anomaly hints, config linting, optional full AI provider analysis, and optional remote webhook.
- Telemetry: health checks, system alerts, and Prometheus-oriented metrics hooks.

Services can run either as Ubuntu Core 24 snaps or as systemd-managed daemons on Ubuntu Server 24.04 VMs. The AI engine is not in the authentication path; if it fails, core networking and AAA continue.
## Vendor Identity Lifecycle

The AegisNAS product VSA namespace is governed by the verified identity lifecycle documented in `vendor-identity.md`. Configuration, generated `dictionary.aegisnas`, packet processing, database evidence, production readiness, and the admin UI share one active PEN. Schema v15 stores assignment and migration evidence. Outbound packets use only the active PEN; inbound legacy decoding is bounded by an explicit deadline. Production readiness requires a matching active assignment record and fails closed for arbitrary non-placeholder IDs.
