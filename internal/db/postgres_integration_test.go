package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

// Run against a disposable PostgreSQL database with CREATE SCHEMA permission.
// Each run owns a unique schema; no existing application tables are modified.
func TestPostgreSQLLiveMigrationsAndRollback(t *testing.T) {
	dsn := os.Getenv("AEGIS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set AEGIS_TEST_POSTGRES_DSN to a disposable PostgreSQL database for live migration tests")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, u.Scheme)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cfg := config.DatabaseConfig{
		Backend: "postgres", DSNRef: "env:AEGIS_TEST_POSTGRES_DSN", SSLMode: u.Query().Get("sslmode"),
		AllowUnsafePostgreSQLSSLMode: true, ConnectTimeoutSeconds: 5,
		StatementTimeoutMilliseconds: 10000, MaxOpenConns: 2,
	}
	if cfg.SSLMode == "" {
		cfg.SSLMode = "require"
	}
	resolve := func(context.Context, string) (string, error) { return u.String(), nil }
	admin, err := OpenDatabaseConfig(ctx, cfg, resolve)
	require.NoError(t, err)
	defer admin.Close()
	schema := fmt.Sprintf("aegis_integration_%d", time.Now().UnixNano())
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, dropOwnedPostgreSQLTestSchema(admin, schema))
	}()
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	handle, err := OpenDatabaseConfig(ctx, cfg, resolve)
	require.NoError(t, err)
	defer handle.Close()
	require.NoError(t, MigrateHandle(handle), "all current migrations must work on real PostgreSQL")
	require.NoError(t, MigrateHandle(handle), "migrations must be idempotent")
	version, err := CurrentSchemaVersionHandle(handle)
	require.NoError(t, err)
	require.Equal(t, LatestSchemaVersion(), version)
	// PostgreSQL's USER keyword is an expression unless the audit column is
	// quoted. Exercise the actual reader as well as fresh and repeat migrations.
	previousDB := DB
	DB = handle
	defer func() { DB = previousDB }()
	t.Setenv("AEGIS_ADMIN_BOOTSTRAP_TOKEN", "isolated-postgres-integration-fixture-not-for-deployment")
	require.NoError(t, Seed(), "fresh PostgreSQL bootstrap must work")
	require.NoError(t, Seed(), "PostgreSQL bootstrap must be idempotent")
	_, err = handle.ExecContext(ctx, `INSERT INTO audit_logs ("user", action) VALUES (?, ?)`, "audit-probe", "integration_probe")
	require.NoError(t, err)
	history, err := ListAuditHistory("audit-probe", "integration_", 10)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Equal(t, "audit-probe", history[0].User)
	stats, err := GetAuditHistoryStats()
	require.NoError(t, err)
	require.Equal(t, 1, stats.UniqueUsers)
	var templateEnabled bool
	require.NoError(t, handle.QueryRowContext(ctx, "SELECT enabled FROM nas_client_capability_templates WHERE name = ?", "default").Scan(&templateEnabled))
	require.True(t, templateEnabled)
	tx, err := handle.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "INSERT INTO roles (name, description) VALUES (?, ?)", "rollback-probe", "temporary")
	require.NoError(t, err, "exercise runtime placeholder rewriting")
	require.NoError(t, tx.Rollback())
	var count int
	require.NoError(t, handle.QueryRowContext(ctx, "SELECT COUNT(*) FROM roles WHERE name = ?", "rollback-probe").Scan(&count))
	require.Zero(t, count, "transaction rollback must leave no role")
	t.Run("PoolStatementTimeout", func(t *testing.T) {
		first, err := handle.Conn(ctx)
		require.NoError(t, err)
		defer first.Close()
		second, err := handle.Conn(ctx)
		require.NoError(t, err)
		defer second.Close()
		for _, conn := range []*sql.Conn{first, second} {
			var timeout int
			require.NoError(t, conn.QueryRowContext(ctx, "SELECT EXTRACT(MILLISECONDS FROM current_setting('statement_timeout')::interval)::int").Scan(&timeout))
			require.Equal(t, 10000, timeout)
			var zone string
			require.NoError(t, conn.QueryRowContext(ctx, "SHOW TimeZone").Scan(&zone))
			require.Equal(t, "UTC", zone)
		}
	})
	t.Run("NASClientLifecycle", testNASClientEnrollmentApprovalLifecycle)
	t.Run("NASClientCapabilityRejection", testNASClientCapabilityTemplateBlocksMissingCapabilities)
	t.Run("NASClientExpiry", testNASClientEnrollmentExpiry)
	t.Run("IntegerWidthUpgrade", func(t *testing.T) {
		// Reproduce a v101 int4 counter with data, then exercise the actual
		// transactional upgrade. Unrelated tables in the schema stay untouched.
		_, err := handle.Exec(`ALTER TABLE roles ALTER COLUMN priority TYPE INTEGER;
			CREATE TABLE unrelated_integer_probe (value INTEGER);
			ALTER TABLE radacct DROP COLUMN aegis_ingest_revision;
			ALTER TABLE radacct DROP COLUMN aegis_packet_source;
			DELETE FROM schema_version WHERE version >= 102;`)
		require.NoError(t, err)
		_, err = handle.Exec(`INSERT INTO roles (name, priority) VALUES ('integer-upgrade-probe', 42)`)
		require.NoError(t, err)
		require.NoError(t, MigrateHandle(handle))
		var priority int64
		require.NoError(t, handle.QueryRow(`SELECT priority FROM roles WHERE name = 'integer-upgrade-probe'`).Scan(&priority))
		require.Equal(t, int64(42), priority)
		_, err = handle.Exec(`UPDATE roles SET priority = ? WHERE name = 'integer-upgrade-probe'`, int64(1)<<40)
		require.NoError(t, err)
		require.NoError(t, handle.QueryRow(`SELECT priority FROM roles WHERE name = 'integer-upgrade-probe'`).Scan(&priority))
		require.Equal(t, int64(1)<<40, priority)
		var dataType string
		require.NoError(t, handle.QueryRow(`SELECT data_type FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = 'unrelated_integer_probe' AND column_name = 'value'`).Scan(&dataType))
		require.Equal(t, "integer", dataType)
		require.NoError(t, MigrateHandle(handle))
	})
}
