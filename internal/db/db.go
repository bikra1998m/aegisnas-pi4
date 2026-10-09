package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
	_ "modernc.org/sqlite"
)

var DB *sql.DB

const (
	sqliteBusyTimeoutMilliseconds = 5000
	defaultSQLiteOpenRetryTimeout = 10 * time.Second
)

func Open(dataSourceName string) (*sql.DB, error) {
	return OpenSQLite(dataSourceName)
}

func OpenSQLite(dataSourceName string) (*sql.DB, error) {
	dir := filepath.Dir(dataSourceName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	handle, err := sql.Open("sqlite", sqliteDataSourceNameWithBusyTimeout(dataSourceName))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), defaultSQLiteOpenRetryTimeout)
	defer cancel()
	if err = pingDatabaseWithBusyRetry(pingCtx, handle); err != nil {
		_ = handle.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if _, err = handle.Exec(fmt.Sprintf("PRAGMA busy_timeout = %d", sqliteBusyTimeoutMilliseconds)); err != nil {
		_ = handle.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	registerHandleDialect(handle, DialectSQLite)
	return handle, nil
}

func OpenConfigured(ctx context.Context, cfg *config.Config) (*sql.DB, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}
	resolver := secrets.NewResolver(secrets.OptionsFromConfig(cfg))
	handle, _, err := openDatabaseConfigWithPlan(ctx, cfg.Database, resolver.Resolve)
	return handle, err
}

func OpenDatabaseConfig(ctx context.Context, cfg config.DatabaseConfig, resolveSecret func(context.Context, string) (string, error)) (*sql.DB, error) {
	handle, _, err := openDatabaseConfigWithPlan(ctx, cfg, resolveSecret)
	return handle, err
}

func openDatabaseConfigWithPlan(ctx context.Context, cfg config.DatabaseConfig, resolveSecret func(context.Context, string) (string, error)) (*sql.DB, ConnectionPlan, error) {
	plan, err := BuildConnectionPlan(ctx, cfg, resolveSecret)
	if err != nil {
		return nil, ConnectionPlan{}, err
	}
	handle, err := openConnectionPlan(ctx, plan)
	if err != nil {
		return nil, ConnectionPlan{}, err
	}
	registerHandleDialect(handle, plan.Dialect)
	return handle, plan, nil
}

func openConnectionPlan(ctx context.Context, plan ConnectionPlan) (*sql.DB, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if plan.Dialect == DialectSQLite {
		dir := filepath.Dir(plan.DataSourceName)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	dataSourceName := plan.DataSourceName
	if plan.Dialect == DialectSQLite {
		dataSourceName = sqliteDataSourceNameWithBusyTimeout(dataSourceName)
	}
	handle, err := sql.Open(plan.Driver, dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", plan.Backend, err)
	}
	applyPoolConfig(handle, plan.Pool)

	pingCtx := ctx
	cancel := func() {}
	if plan.ConnectTimeout > 0 {
		pingCtx, cancel = context.WithTimeout(ctx, plan.ConnectTimeout)
	}
	defer cancel()
	if plan.Dialect == DialectSQLite {
		err = pingDatabaseWithBusyRetry(pingCtx, handle)
	} else {
		err = handle.PingContext(pingCtx)
	}
	if err != nil {
		_ = handle.Close()
		return nil, fmt.Errorf("ping %s database: %w", plan.Backend, err)
	}
	switch plan.Dialect {
	case DialectSQLite:
		if _, err = handle.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout = %d", sqliteBusyTimeoutMilliseconds)); err != nil {
			_ = handle.Close()
			return nil, fmt.Errorf("set busy timeout: %w", err)
		}
	case DialectPostgreSQL:
		if plan.StatementTimeoutMilliseconds > 0 {
			if _, err = handle.ExecContext(ctx, fmt.Sprintf("SET statement_timeout = %d", plan.StatementTimeoutMilliseconds)); err != nil {
				_ = handle.Close()
				return nil, fmt.Errorf("set PostgreSQL statement timeout: %w", err)
			}
		}
	}
	return handle, nil
}

func sqliteDataSourceNameWithBusyTimeout(dataSourceName string) string {
	trimmed := strings.TrimSpace(dataSourceName)
	if trimmed == "" || strings.Contains(strings.ToLower(trimmed), "busy_timeout") {
		return dataSourceName
	}
	separator := "?"
	if strings.Contains(trimmed, "?") {
		separator = "&"
	}
	return dataSourceName + separator + fmt.Sprintf("_pragma=busy_timeout(%d)", sqliteBusyTimeoutMilliseconds)
}

func pingDatabaseWithBusyRetry(ctx context.Context, handle *sql.DB) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	for {
		err := handle.PingContext(ctx)
		if err == nil {
			return nil
		}
		if !isSQLiteBusyError(err) {
			return err
		}
		lastErr = err
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			if lastErr != nil {
				return lastErr
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "sqlite_busy") ||
		strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database is busy")
}

func Init(dataSourceName string) error {
	handle, err := Open(dataSourceName)
	if err != nil {
		return err
	}
	DB = handle
	setActiveConnectionInfo(ConnectionInfo{
		Backend:        string(DialectSQLite),
		Driver:         "sqlite",
		Dialect:        string(DialectSQLite),
		LocalStatePath: dataSourceName,
		Pool:           PoolConfigFromDatabaseConfig(config.DatabaseConfig{}),
		ConnectedAt:    time.Now().UTC(),
	})
	return nil
}

func InitConfigured(ctx context.Context, cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is required")
	}
	resolver := secrets.NewResolver(secrets.OptionsFromConfig(cfg))
	handle, plan, err := openDatabaseConfigWithPlan(ctx, cfg.Database, resolver.Resolve)
	if err != nil {
		return err
	}
	DB = handle
	setActiveConnectionInfo(plan.ConnectionInfo())
	return nil
}

func Close() error {
	if DB != nil {
		err := DB.Close()
		forgetHandle(DB)
		DB = nil
		setActiveConnectionInfo(ConnectionInfo{})
		return err
	}
	return nil
}

func GetDB() *sql.DB {
	if DB == nil {
		panic("database not initialized")
	}
	return DB
}

func applyPoolConfig(handle *sql.DB, pool PoolConfig) {
	if pool.MaxOpenConns > 0 {
		handle.SetMaxOpenConns(pool.MaxOpenConns)
	}
	if pool.MaxIdleConns > 0 {
		handle.SetMaxIdleConns(pool.MaxIdleConns)
	}
	if pool.ConnMaxLifetime > 0 {
		handle.SetConnMaxLifetime(pool.ConnMaxLifetime)
	}
	if pool.ConnMaxIdleTime > 0 {
		handle.SetConnMaxIdleTime(pool.ConnMaxIdleTime)
	}
}

func normalizeBackend(value string) Dialect {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "sqlite":
		return DialectSQLite
	case "postgres", "postgresql":
		return DialectPostgreSQL
	default:
		return DialectUnknown
	}
}
