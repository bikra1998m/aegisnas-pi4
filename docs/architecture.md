# Architecture Overview

AegisNAS Pi4 is divided into operational planes so each service has a clear boundary and safe failure mode.

- Gateway: nftables firewall, NAT, VLAN routing, captive redirect hooks, and config rollback.
- AAA: FreeRADIUS configuration generation, PAP, accounting, EAP templates, local users, vouchers, and LDAP-backed identity.
- Portal: guest login, voucher login, status, success, logout, branding, and rate limiting.
- Session: active session tracking, timeouts, concurrent session checks, and admin termination.
- Policy: deterministic role, source, SSID, auth-method, VLAN, timeout, bandwidth, quarantine, and portal-profile decisions.
- Admin API and UI: CRUD, staged changes, validation, apply, rollback, backup/restore, alerts, and AI recommendations.
- AI-lite: advisory auth-failure grouping, anomaly hints, config linting, and optional remote webhook.
- Telemetry: health checks, system alerts, and Prometheus-oriented metrics hooks.

Services can run either as Ubuntu Core 24 snaps or as systemd-managed daemons on Ubuntu Server 24.04 VMs. AI-lite is not in the authentication path; if it fails, core networking and AAA continue.
