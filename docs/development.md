# Development Guide

## Prerequisites

- Go 1.25+
- Node.js 22+
- npm 10+
- make, when using Makefile targets

The project uses `modernc.org/sqlite`, so Go builds and tests do not need CGO or a local C compiler.

## Setup

```powershell
Copy-Item configs\config.example.yaml configs\config.yaml
go mod download
go test ./...
cd web/admin-ui
npm ci
npm run build
```

If PowerShell blocks `npm.ps1`, use `npm.cmd`.

## Database

```powershell
go run ./cmd/aegis-admin migrate --config configs/config.yaml
$env:AEGIS_ADMIN_BOOTSTRAP_TOKEN='replace-with-a-long-random-token'
go run ./cmd/aegis-admin seed --config configs/config.yaml
```

The seed command creates default roles, policies, bandwidth profiles, portal profiles, identity sources, a localhost RADIUS client, and a hashed bootstrap API token.

## Running Services

```powershell
go run ./cmd/aegis-admin-api run --config configs/config.yaml
go run ./cmd/aegis-gateway dry-run --config configs/config.yaml
go run ./cmd/aegis-radius run --config configs/config.yaml
go run ./cmd/aegis-portal run --config configs/config.yaml
```

## Testing

```powershell
$env:CGO_ENABLED='0'
go test ./...
cd web/admin-ui
npm run build
npm audit --audit-level=moderate
```

## Admin UI Development

The UI is a Vite/React app. All operational pages live in `web/admin-ui/src/pages`. Reusable list/modal CRUD behavior lives in `web/admin-ui/src/components/CrudPage.tsx`.

When adding a new config object:

1. Add list/create/update/delete handlers in `internal/adminapi`.
2. Add routes under `/api/v1` in `cmd/aegis-admin-api`.
3. Add a page in `web/admin-ui/src/pages`.
4. Add the page to `App.tsx` and `Sidebar.tsx`.
5. Document the operator workflow.
6. Run Go tests, UI build, and npm audit.
