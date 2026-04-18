# Production Readiness Update

Date: 2026-04-17

## Documentation Reviewed

- `C:\Users\BIKRAM MAITY\Downloads\ai_nas_system_architecture.svg`
- `C:\Users\BIKRAM MAITY\Downloads\ai_nas_blueprint.html`
- `C:\Users\BIKRAM MAITY\Downloads\aegisnas_pi4_development_handbook.docx`

The common requirements from those documents are:

- Raspberry Pi 4 class target with strict memory and I/O budget.
- Go services, SQLite local state, generated configs, snap packaging, and Ubuntu Core image workflow.
- Deterministic authentication, policy, and session decisions.
- Advisory AI only; AI must never block authentication or networking.
- Admin UI for manual operation of every major object.
- Safe validate, apply, rollback, backup, restore, and audit flows.

## Readiness Before This Update

The project was not production-ready at the start of this pass.

Main blockers found:

- Go test/build was broken by missing imports, wrong package paths, duplicate RADIUS helpers, missing modules, and a CGO-only SQLite driver on a no-C-compiler Windows workspace.
- The admin UI imported pages that did not exist.
- Several admin API objects supported create only, not edit/delete.
- Token auth did not set the user context required by staging, which could panic on writes.
- Config rollback returned a placeholder response instead of restoring data.
- Backups lacked a manifest verification path.
- CORS allowed wildcard origins with credentials.
- UI dependencies had a moderate audit finding through the old Vite/esbuild chain.
- Backup and operations docs were incomplete.

## Backend Updates

1. Replaced `mattn/go-sqlite3` with `modernc.org/sqlite` so the project builds with `CGO_ENABLED=0`.
2. Added missing Go module declarations and tidied `go.mod` / `go.sum`.
3. Fixed broken package imports for the session service.
4. Fixed compile errors in logging, telemetry, AI-lite, portal auth, policy, dnsmasq, firewall, and backup code.
5. Added hashed API token lookup using `sha256:<hex>` values while keeping legacy plaintext lookup for old databases.
6. Updated seed behavior so the bootstrap token comes from `AEGIS_ADMIN_BOOTSTRAP_TOKEN` or a generated printed value.
7. Added `/api/v1/auth/validate`.
8. Added update/delete handlers and routes for vouchers, roles, policies, identity sources, portal profiles, and bandwidth profiles.
9. Added admin API endpoints for config JSON export/import.
10. Added admin API endpoints for AI recommendation list/acknowledge.
11. Implemented real config snapshots for staged apply.
12. Implemented checksum-verified rollback that restores captured config tables.
13. Added audit rows for staging, apply, rollback, session termination, alert acknowledgement, AI acknowledgement, and backup import.
14. Hardened admin CORS defaults and added `AEGIS_ADMIN_ALLOWED_ORIGINS`.
15. Made backup archives include `manifest.json` with SHA-256 checksums.
16. Added restore manifest verification and safe archive path handling.
17. Switched logging initialization to an explicit zap core so file/stdout output is actually used.
18. Made session timeout enforcement work with the pure-Go SQLite driver's time storage behavior.

## Admin UI Updates

1. Removed the undeclared `lucide-react` dependency from UI code.
2. Added a reusable CRUD page component with list table, add/edit/delete modals, validation, JSON editor support, checkboxes, and password handling.
3. Added the missing pages:
   - Portal profiles
   - Users
   - Vouchers
   - Roles
   - Bandwidth profiles
   - Policies
   - Identity sources
   - Alerts
   - Config revisions
   - Backups
   - AI recommendations
4. Reworked VLANs to use the same table and modal pattern.
5. Reworked sessions with a terminate button.
6. Added a global pending changes bar with validate and apply actions.
7. Added backup JSON download/upload from the UI.
8. Added rollback from the UI.
9. Upgraded Vite and `@vitejs/plugin-react`; `npm audit --audit-level=moderate` now reports zero vulnerabilities.

## Documentation Updates

1. Rewrote `README.md` with the current build, UI, and production readiness status.
2. Rewrote `docs/operations.md` with service, UI, monitoring, update, and backup workflows.
3. Rewrote `docs/security.md` with token, CORS, revision, LDAP, firewall, backup, and AI-plane guidance.
4. Rewrote `docs/backup-restore.md` with CLI and UI restore procedures.
5. Rewrote `docs/development.md` with the current Go/Node requirements, test commands, and page-extension workflow.
6. Added this update log.

## Verification Performed

```powershell
$env:CGO_ENABLED='0'
go test ./...
```

Result: pass.

```powershell
cd web/admin-ui
npm run build
npm audit --audit-level=moderate --json
```

Result: production build pass; audit reports zero vulnerabilities.

## Production Deployment Prerequisites

Before installing at a real site, complete these site-specific items:

- Set `AEGIS_ADMIN_BOOTSTRAP_TOKEN` and rotate any legacy/plaintext API tokens.
- Set `AEGIS_ADMIN_ALLOWED_ORIGINS` to the final admin UI origin.
- Install TLS certificates for the admin UI/API and LDAPS.
- Replace test RADIUS client secrets.
- Confirm VLAN IDs, interface names, DHCP pools, and management VLAN access.
- Build/sign snaps and Ubuntu Core image assets for the target fleet.
- Run a lab acceptance test with the real AP model, managed switch, USB NIC mode, and at least one restore drill.

## Current Status

The repository is no longer blocked by build failures or missing manual UI operations. It is ready for production packaging and pilot deployment once the site-specific secrets, certificates, network values, and Ubuntu Core signing workflow are supplied.
