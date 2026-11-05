# Development Guide

Branches named `codex/roadmap-*` run the ordinary regression, PostgreSQL and
release-evidence workflows on GitHub. CI runs every existing browser spec and
retains Go/Python/browser results, including failures. These are development
checks; the signing job still requires a manually dispatched run on `main` and
a passing security gate. A successful code checkpoint is not release admission.

For admission/re-verification changes, run the complete Python regression suite
and the Linux permission cases in [release re-verification](release-reverification.md).
Mocked-signature fixtures validate software paths; a trusted signed candidate
and hosted workflow remain separate required evidence.

For appliance supply-chain changes, run the Python regression suite described
in [artifact inventory](appliance-artifact-inventory.md). Snap build helpers use
the exact Go version in `go.mod`; the [snap packaging guide](../snaps/README.md)
distinguishes compiler/contract checks from actual Snapcraft and image validation.

For recovery changes, run the affected Go suites and the actual CLI fixture in
the [authenticated recovery staging guide](authenticated-recovery-staging.md).
The fixture creates a new SQLite database and never changes deployed services.
Windows ACL enforcement, production activation, and PostgreSQL backup are
separate gates; an encrypted staging result does not certify those behaviors.

## Prerequisites

- Go 1.26.10+ (the minimum security patch is pinned in `go.mod` and `go.work`)
- Node.js 22+
- npm 10+
- make, when using Makefile targets

The project uses `modernc.org/sqlite`, so Go builds and tests do not need CGO or a local C compiler.

The admin UI uses Tailwind 4 and React Router 7. Tailwind 4's browser baseline
applies; validate the browsers used by your operators before rolling out a new
appliance UI. The PostCSS plugin is `@tailwindcss/postcss`.

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

On memory-constrained development hosts, use `GOMAXPROCS=2` and
`go build -p=1 ./...`; avoid running compiler-heavy builds concurrently.

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

The checked-in Quick Start configuration is covered by
`TestRepositoryExampleConfigLoadsAndValidates`. The opt-in PostgreSQL migration
and rollback integration test requires `AEGIS_TEST_POSTGRES_DSN` pointing to a
disposable database with CREATE SCHEMA permission. It creates and removes its
own unique schema; absence of the DSN is reported as a skip, not live evidence.
It also runs NAS-client enrollment/refresh, approval, heartbeat, lists/events,
revocation, capability rejection and expiry against the live PostgreSQL handle.
These assertions are shared with SQLite tests. Run the complete live slice with
`go test -count=1 -v ./internal/db -run '^TestPostgreSQLLiveMigrationsAndRollback$'`.
This slice does not establish service-wide PostgreSQL compatibility.

For dependency inventories, vulnerability policy and signed candidates, see
[supply-chain-release-security.md](supply-chain-release-security.md).

The UI is a Vite/React app. All operational pages live in `web/admin-ui/src/pages`. Reusable list/modal CRUD behavior lives in `web/admin-ui/src/components/CrudPage.tsx`.

When adding a new config object:

1. Add list/create/update/delete handlers in `internal/adminapi`.
2. Add routes under `/api/v1` in `cmd/aegis-admin-api`.
3. Add a page in `web/admin-ui/src/pages`.
4. Add the page to `App.tsx` and `Sidebar.tsx`.
5. Document the operator workflow.
6. Run Go tests, UI build, and npm audit.
