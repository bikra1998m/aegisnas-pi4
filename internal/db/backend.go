package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

type Dialect string

const (
	DialectUnknown    Dialect = "unknown"
	DialectSQLite     Dialect = "sqlite"
	DialectPostgreSQL Dialect = "postgres"
)

const postgresDriverName = "aegis-pgx"

type PoolConfig struct {
	MaxOpenConns            int           `json:"max_open_conns"`
	MaxIdleConns            int           `json:"max_idle_conns"`
	ConnMaxLifetime         time.Duration `json:"-"`
	ConnMaxIdleTime         time.Duration `json:"-"`
	ConnMaxLifetimeSec      int           `json:"conn_max_lifetime_seconds"`
	ConnMaxIdleTimeSec      int           `json:"conn_max_idle_time_seconds"`
	ConnectTimeoutSec       int           `json:"connect_timeout_seconds"`
	StatementTimeoutMS      int           `json:"statement_timeout_milliseconds"`
	MigrationLockTimeoutSec int           `json:"migration_lock_timeout_seconds"`
}

type ConnectionPlan struct {
	Backend                      string
	Dialect                      Dialect
	Driver                       string
	DataSourceName               string
	DataSourceFingerprint        string
	LocalStatePath               string
	DSNRef                       string
	InlineDSN                    bool
	SSLMode                      string
	TLSRequired                  bool
	UnsafeSSLModeAllowed         bool
	Pool                         PoolConfig
	ConnectTimeout               time.Duration
	StatementTimeoutMilliseconds int
	CreatedAt                    time.Time
}

type ConnectionInfo struct {
	Backend              string     `json:"backend"`
	Driver               string     `json:"driver"`
	Dialect              string     `json:"dialect"`
	LocalStatePath       string     `json:"local_state_path,omitempty"`
	DSNRefSet            bool       `json:"dsn_ref_set"`
	InlineDSNSet         bool       `json:"inline_dsn_set"`
	DSNFingerprint       string     `json:"dsn_fingerprint,omitempty"`
	SSLMode              string     `json:"sslmode,omitempty"`
	TLSRequired          bool       `json:"tls_required"`
	UnsafeSSLModeAllowed bool       `json:"unsafe_sslmode_allowed"`
	Pool                 PoolConfig `json:"pool"`
	ConnectedAt          time.Time  `json:"connected_at,omitempty"`
}

type StatusReport struct {
	SchemaVersion     int            `json:"schema_version"`
	GeneratedAt       string         `json:"generated_at"`
	Status            string         `json:"status"`
	Message           string         `json:"message"`
	ConfiguredBackend string         `json:"configured_backend"`
	Active            ConnectionInfo `json:"active"`
	PoolStats         sql.DBStats    `json:"pool_stats,omitempty"`
	ReadyForHA        bool           `json:"ready_for_ha"`
	Warnings          []string       `json:"warnings,omitempty"`
}

var (
	handleDialects sync.Map
	activeInfoMu   sync.RWMutex
	activeInfo     ConnectionInfo
)

func BuildConnectionPlan(ctx context.Context, cfg config.DatabaseConfig, resolveSecret func(context.Context, string) (string, error)) (ConnectionPlan, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dialect := normalizeBackend(cfg.Backend)
	if dialect == DialectUnknown {
		return ConnectionPlan{}, fmt.Errorf("database backend %q is invalid", cfg.Backend)
	}
	pool := PoolConfigFromDatabaseConfig(cfg)
	plan := ConnectionPlan{
		Backend:                      string(dialect),
		Dialect:                      dialect,
		LocalStatePath:               strings.TrimSpace(cfg.Path),
		SSLMode:                      normalizedSSLMode(cfg.SSLMode),
		TLSRequired:                  cfg.ProductionRequireTLS,
		UnsafeSSLModeAllowed:         cfg.AllowUnsafePostgreSQLSSLMode,
		Pool:                         pool,
		ConnectTimeout:               time.Duration(cfg.ConnectTimeoutSeconds) * time.Second,
		StatementTimeoutMilliseconds: cfg.StatementTimeoutMilliseconds,
		CreatedAt:                    time.Now().UTC(),
	}
	switch dialect {
	case DialectSQLite:
		if strings.TrimSpace(cfg.Path) == "" {
			return ConnectionPlan{}, fmt.Errorf("database.path cannot be empty")
		}
		plan.Driver = "sqlite"
		plan.DataSourceName = strings.TrimSpace(cfg.Path)
	case DialectPostgreSQL:
		dsn := strings.TrimSpace(cfg.DSN)
		if ref := strings.TrimSpace(cfg.DSNRef); ref != "" {
			if resolveSecret == nil {
				return ConnectionPlan{}, fmt.Errorf("database.dsn_ref requires a secret resolver")
			}
			resolved, err := resolveSecret(ctx, ref)
			if err != nil {
				return ConnectionPlan{}, fmt.Errorf("resolve database.dsn_ref: %w", err)
			}
			dsn = strings.TrimSpace(resolved)
			plan.DSNRef = ref
		} else if dsn != "" {
			plan.InlineDSN = true
		}
		if dsn == "" {
			return ConnectionPlan{}, fmt.Errorf("PostgreSQL DSN is required")
		}
		dsn = ensurePostgreSQLSSLMode(dsn, plan.SSLMode)
		plan.Driver = postgresDriverName
		plan.DataSourceName = dsn
		plan.DataSourceFingerprint = fingerprintDSN(dsn)
	default:
		return ConnectionPlan{}, fmt.Errorf("unsupported database backend %q", cfg.Backend)
	}
	return plan, nil
}

func PoolConfigFromDatabaseConfig(cfg config.DatabaseConfig) PoolConfig {
	return PoolConfig{
		MaxOpenConns:            cfg.MaxOpenConns,
		MaxIdleConns:            cfg.MaxIdleConns,
		ConnMaxLifetime:         time.Duration(cfg.ConnMaxLifetimeSeconds) * time.Second,
		ConnMaxIdleTime:         time.Duration(cfg.ConnMaxIdleTimeSeconds) * time.Second,
		ConnMaxLifetimeSec:      cfg.ConnMaxLifetimeSeconds,
		ConnMaxIdleTimeSec:      cfg.ConnMaxIdleTimeSeconds,
		ConnectTimeoutSec:       cfg.ConnectTimeoutSeconds,
		StatementTimeoutMS:      cfg.StatementTimeoutMilliseconds,
		MigrationLockTimeoutSec: cfg.MigrationLockTimeoutSeconds,
	}
}

func (p ConnectionPlan) ConnectionInfo() ConnectionInfo {
	return ConnectionInfo{
		Backend:              p.Backend,
		Driver:               p.Driver,
		Dialect:              string(p.Dialect),
		LocalStatePath:       p.LocalStatePath,
		DSNRefSet:            strings.TrimSpace(p.DSNRef) != "",
		InlineDSNSet:         p.InlineDSN,
		DSNFingerprint:       p.DataSourceFingerprint,
		SSLMode:              p.SSLMode,
		TLSRequired:          p.TLSRequired,
		UnsafeSSLModeAllowed: p.UnsafeSSLModeAllowed,
		Pool:                 p.Pool,
		ConnectedAt:          p.CreatedAt,
	}
}

func BuildStatusReport(cfg *config.Config) StatusReport {
	report := StatusReport{
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Status:        "ready",
		Message:       "Database data plane is configured.",
		ReadyForHA:    false,
	}
	if cfg != nil {
		report.ConfiguredBackend = string(normalizeBackend(cfg.Database.Backend))
		if cfg.Database.ProductionRequirePostgreSQL && normalizeBackend(cfg.Database.Backend) != DialectPostgreSQL {
			report.Status = "blocked"
			report.Message = "Production PostgreSQL is required by configuration, but the active backend is not PostgreSQL."
			report.Warnings = append(report.Warnings, "Set database.backend to postgres and configure database.dsn_ref before production sign-off.")
		}
		if normalizeBackend(cfg.Database.Backend) == DialectPostgreSQL {
			if strings.TrimSpace(cfg.Database.DSNRef) == "" {
				report.Status = maxDatabaseStatus(report.Status, "degraded")
				report.Warnings = append(report.Warnings, "PostgreSQL is configured without database.dsn_ref; use a secret reference for production.")
			}
			sslMode := normalizedSSLMode(cfg.Database.SSLMode)
			if cfg.Database.ProductionRequireTLS && !cfg.Database.AllowUnsafePostgreSQLSSLMode && !postgresSSLModeIsTLS(sslMode) {
				report.Status = "blocked"
				report.Warnings = append(report.Warnings, "PostgreSQL TLS is required, but database.sslmode is not require, verify-ca, or verify-full.")
			}
		}
	}
	report.Active = ActiveConnectionInfo()
	if DB != nil {
		report.PoolStats = DB.Stats()
		version, err := CurrentSchemaVersion()
		if err != nil {
			report.Status = "blocked"
			report.Message = "Database schema version cannot be read: " + err.Error()
		} else if version != LatestSchemaVersion() {
			report.Status = "blocked"
			report.Message = fmt.Sprintf("Database schema version %d does not match expected version %d.", version, LatestSchemaVersion())
		}
	}
	if report.Active.Backend == string(DialectPostgreSQL) && report.Active.DSNRefSet && postgresSSLModeIsTLS(report.Active.SSLMode) {
		report.ReadyForHA = true
	}
	if report.Status == "ready" && report.Active.Backend == string(DialectSQLite) {
		report.Status = "degraded"
		report.Message = "SQLite is active; suitable for lab and lite nodes, but not an enterprise multi-node data plane."
		report.Warnings = append(report.Warnings, "Use PostgreSQL for enterprise HA and long-retention deployments.")
	}
	return report
}

func ActiveConnectionInfo() ConnectionInfo {
	activeInfoMu.RLock()
	defer activeInfoMu.RUnlock()
	return activeInfo
}

func setActiveConnectionInfo(info ConnectionInfo) {
	activeInfoMu.Lock()
	defer activeInfoMu.Unlock()
	activeInfo = info
}

func SetActiveConnectionInfoForTest(info ConnectionInfo) {
	setActiveConnectionInfo(info)
}

func registerHandleDialect(handle *sql.DB, dialect Dialect) {
	if handle != nil {
		handleDialects.Store(handle, dialect)
	}
}

func forgetHandle(handle *sql.DB) {
	if handle != nil {
		handleDialects.Delete(handle)
	}
}

func DialectForHandle(handle *sql.DB) Dialect {
	if handle == nil {
		return DialectUnknown
	}
	if value, ok := handleDialects.Load(handle); ok {
		if dialect, ok := value.(Dialect); ok {
			return dialect
		}
	}
	return DialectSQLite
}

func normalizedSSLMode(value string) string {
	mode := strings.ToLower(strings.TrimSpace(value))
	if mode == "" {
		return "verify-full"
	}
	return mode
}

func postgresSSLModeIsTLS(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "require", "verify-ca", "verify-full":
		return true
	default:
		return false
	}
}

func ensurePostgreSQLSSLMode(dsn, sslMode string) string {
	sslMode = normalizedSSLMode(sslMode)
	if strings.Contains(strings.ToLower(dsn), "sslmode=") {
		return dsn
	}
	parsed, err := url.Parse(dsn)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		q := parsed.Query()
		q.Set("sslmode", sslMode)
		parsed.RawQuery = q.Encode()
		return parsed.String()
	}
	separator := " "
	if strings.HasSuffix(strings.TrimSpace(dsn), " ") {
		separator = ""
	}
	return dsn + separator + "sslmode=" + sslMode
}

func fingerprintDSN(dsn string) string {
	sum := sha256.Sum256([]byte(dsn))
	return hex.EncodeToString(sum[:])
}

func maxDatabaseStatus(current, candidate string) string {
	weight := map[string]int{"ready": 0, "degraded": 1, "blocked": 2}
	if weight[candidate] > weight[current] {
		return candidate
	}
	return current
}
