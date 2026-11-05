package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

// initRuntimeTestDB runs the same application assertions against either backend.
// The opt-in PostgreSQL target must be disposable and permit CREATE SCHEMA.
// Every fixture owns its own schema; no existing application data is migrated.
func initRuntimeTestDB(t *testing.T, sqlitePath string) error {
	t.Helper()
	dsn := os.Getenv("AEGIS_TEST_RUNTIME_POSTGRES_DSN")
	if dsn == "" {
		return Init(sqlitePath)
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return fmt.Errorf("runtime PostgreSQL fixture requires a postgres URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg := config.DatabaseConfig{Backend: "postgres", DSNRef: "env:AEGIS_TEST_RUNTIME_POSTGRES_DSN",
		SSLMode: u.Query().Get("sslmode"), AllowUnsafePostgreSQLSSLMode: true,
		ConnectTimeoutSeconds: 5, StatementTimeoutMilliseconds: 15000, MaxOpenConns: 2}
	if cfg.SSLMode == "" {
		cfg.SSLMode = "require"
	}
	resolve := func(context.Context, string) (string, error) { return u.String(), nil }
	admin, err := OpenDatabaseConfig(ctx, cfg, resolve)
	if err != nil {
		return err
	}
	schema := fmt.Sprintf("aegis_runtime_%d", time.Now().UnixNano())
	if _, err = admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		return err
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	handle, err := OpenDatabaseConfig(ctx, cfg, resolve)
	t.Cleanup(func() {
		if handle != nil {
			_ = handle.Close()
			forgetHandle(handle)
			if DB == handle {
				DB = nil
			}
		}
		if err := dropOwnedPostgreSQLTestSchema(admin, schema); err != nil {
			t.Errorf("cleanup owned PostgreSQL fixture schema: %v", err)
		}
		_ = admin.Close()
	})
	if err != nil {
		return err
	}
	DB = handle
	t.Log("runtime database: PostgreSQL (isolated schema)")
	return nil
}

// A fixture contains hundreds of relation/index files. Give only its teardown
// transaction a larger budget on slow shared lab storage. Application queries
// retain the configured timeouts and cleanup must still succeed for a PASS.
func dropOwnedPostgreSQLTestSchema(handle *sql.DB, schema string) error {
	cleanup, stop := context.WithTimeout(context.Background(), 60*time.Second)
	defer stop()
	tx, err := handle.BeginTx(cleanup, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(cleanup, "SET LOCAL statement_timeout = '60s'"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(cleanup, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
		return err
	}
	return tx.Commit()
}
