package db

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestBuildConnectionPlanPostgreSQLUsesSecretRefAndRedactsDSN(t *testing.T) {
	cfg := config.DatabaseConfig{
		Backend:                      "postgres",
		DSNRef:                       "env:AEGIS_SECRET_POSTGRES_DSN",
		SSLMode:                      "verify-ca",
		MaxOpenConns:                 40,
		MaxIdleConns:                 8,
		ConnectTimeoutSeconds:        3,
		StatementTimeoutMilliseconds: 15000,
		ProductionRequireTLS:         true,
	}
	plan, err := BuildConnectionPlan(context.Background(), cfg, func(context.Context, string) (string, error) {
		return "postgres://aegis:secret@db.example.test:5432/aegisnas", nil
	})
	require.NoError(t, err)
	assert.Equal(t, DialectPostgreSQL, plan.Dialect)
	assert.Equal(t, postgresDriverName, plan.Driver)
	assert.Contains(t, plan.DataSourceName, "sslmode=verify-ca")
	assert.NotContains(t, plan.ConnectionInfo().DSNFingerprint, "secret")
	assert.True(t, plan.ConnectionInfo().DSNRefSet)
	assert.False(t, plan.ConnectionInfo().InlineDSNSet)
	assert.Equal(t, 40, plan.Pool.MaxOpenConns)
}

func TestPostgreSQLQueryRewrite(t *testing.T) {
	query := `INSERT OR IGNORE INTO roles (name, description) VALUES (?, '? literal');
SELECT * FROM sessions WHERE username = ? AND created_at > datetime('now', '-7 days') AND note = '?' -- ?
`
	rewritten := rewritePostgreSQLQuery(query)
	assert.Contains(t, rewritten, "INSERT INTO roles")
	assert.Contains(t, rewritten, "ON CONFLICT DO NOTHING")
	assert.Contains(t, rewritten, "VALUES ($1, '? literal')")
	assert.Contains(t, rewritten, "username = $2")
	assert.Contains(t, rewritten, "INTERVAL '7 days'")
	assert.Contains(t, rewritten, "note = '?' -- ?")
}

func TestPostgreSQLSchemaSQL(t *testing.T) {
	converted := PostgreSQLSchemaSQL(schemaV1 + schemaV15 + schemaV17)
	assert.NotContains(t, converted, "AUTOINCREMENT")
	assert.NotContains(t, converted, "DATETIME")
	assert.NotContains(t, converted, "INSERT OR IGNORE")
	assert.Contains(t, converted, "BIGSERIAL PRIMARY KEY")
	assert.Contains(t, converted, "TIMESTAMPTZ")
	assert.Contains(t, converted, "ON CONFLICT DO NOTHING")
	assert.Contains(t, converted, "WHERE active = TRUE")
	assert.False(t, strings.Contains(converted, "BOOLEAN DEFAULT 0"))
	assert.False(t, strings.Contains(converted, "BOOLEAN DEFAULT 1"))
}

func TestBuildStatusReportRedactsActivePostgreSQLDSN(t *testing.T) {
	setActiveConnectionInfo(ConnectionInfo{
		Backend:        string(DialectPostgreSQL),
		Driver:         postgresDriverName,
		Dialect:        string(DialectPostgreSQL),
		DSNRefSet:      true,
		DSNFingerprint: strings.Repeat("a", 64),
		SSLMode:        "verify-full",
		TLSRequired:    true,
	})
	t.Cleanup(func() { setActiveConnectionInfo(ConnectionInfo{}) })
	report := BuildStatusReport(&config.Config{Database: config.DatabaseConfig{
		Backend:              "postgres",
		DSNRef:               "env:AEGIS_SECRET_POSTGRES_DSN",
		SSLMode:              "verify-full",
		ProductionRequireTLS: true,
	}})
	assert.Equal(t, "postgres", report.Active.Backend)
	assert.True(t, report.Active.DSNRefSet)
	assert.Equal(t, strings.Repeat("a", 64), report.Active.DSNFingerprint)
	assert.NotContains(t, report.Message, "AEGIS_SECRET_POSTGRES_DSN")
}
