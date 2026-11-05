package radius

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPostgreSQLAccountingGeneration(t *testing.T) {
	cfg := &config.Config{Database: config.DatabaseConfig{Backend: "postgres", DSN: "postgres://r:fixture@localhost/db"}}
	g := NewGenerator(cfg)
	disabled, err := g.renderModsPostgreSQL()
	require.NoError(t, err)
	require.NotContains(t, disabled, "INSERT INTO")
	cfg.Radius.SQLAccounting.Enabled = true
	module, err := g.renderModsPostgreSQL()
	require.NoError(t, err)
	require.Contains(t, module, "auto_escape = yes")
	require.Contains(t, module, "\tpost-auth {\n")
	require.NotContains(t, module, "\tpostauth {")
	for _, line := range strings.Split(module, "\n") {
		require.Less(t, len(line), 8000, "FreeRADIUS 3 configuration line length")
	}
	for _, name := range []string{"start", "interim-update", "stop", "accounting-on", "accounting-off"} {
		require.Contains(t, module, "\t\t\t"+name+" {")
	}
	for _, secret := range []string{"User-Password", "CHAP-Password", "MS-CHAP", "Module-Failure-Message"} {
		require.NotContains(t, module, secret)
	}
	site, err := g.renderSitesDefault()
	require.NoError(t, err)
	require.Contains(t, site, postgresAccountingUnlang)
	require.Contains(t, site, postgresPostAuthUnlang)
	require.Contains(t, site, "Response-Packet-Type := Do-Not-Respond")
	cfg.Radius.SQLAccounting.Enabled = false
	site, err = g.renderSitesDefault()
	require.NoError(t, err)
	require.NotContains(t, site, postgresAccountingUnlang)
	require.NotContains(t, site, postgresPostAuthUnlang)
}

// Opt-in integration entry point. The PostgreSQL server must be the disposable
// cluster inside the harness root; migration cannot run against an arbitrary DSN.
func TestPostgreSQLAccountingLiveFixture(t *testing.T) {
	root := os.Getenv("AEGIS_RADIUS_SQL_FIXTURE_ROOT")
	if root == "" {
		t.Skip("isolated PostgreSQL accounting packet fixture not requested")
	}
	cfg := &config.Config{Database: config.DatabaseConfig{Backend: "postgres",
		DSN: os.Getenv("AEGIS_RADIUS_SQL_FIXTURE_ADMIN_DSN"), SSLMode: "verify-full",
		ProductionRequireTLS: true, ConnectTimeoutSeconds: 3, StatementTimeoutMilliseconds: 15000,
		MaxOpenConns: 2}}
	require.NoError(t, db.InitConfigured(context.Background(), cfg))
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	var dataDirectory string
	require.NoError(t, db.DB.QueryRow("SHOW data_directory").Scan(&dataDirectory))
	require.Equal(t, filepath.Join(root, "pgdata"), filepath.Clean(dataDirectory))
	switch os.Getenv("AEGIS_RADIUS_SQL_FIXTURE_ACTION") {
	case "prepare":
		require.NoError(t, db.Migrate())
		_, err := db.DB.Exec("REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO radius; GRANT SELECT, INSERT, UPDATE ON radacct, radpostauth TO radius; GRANT USAGE, SELECT ON SEQUENCE radacct_radacctid_seq, radpostauth_id_seq TO radius")
		require.NoError(t, err)
		cfg.Database.DSN = os.Getenv("AEGIS_RADIUS_PG_FIXTURE_DSN")
		cfg.Database.StatementTimeoutMilliseconds = 1500
		cfg.Radius.SQLAccounting.Enabled = true
		g := NewGenerator(cfg)
		module, err := g.renderModsPostgreSQL()
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(root, "sql"), []byte(module), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(root, "accounting.inc"), []byte(postgresAccountingUnlang), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(root, "postauth.inc"), []byte(postgresPostAuthUnlang), 0600))
		site, err := g.renderSitesDefault()
		require.NoError(t, err)
		require.Contains(t, site, postgresAccountingUnlang)
		require.Contains(t, site, postgresPostAuthUnlang)
		require.NoError(t, os.WriteFile(filepath.Join(root, "generated-default"), []byte(site), 0600))
	case "reconcile":
		result, err := db.ReconcileFreeRADIUSAccounting(500)
		require.NoError(t, err)
		require.Zero(t, result.ErrorCount, result.LastError)
		encoded, err := json.Marshal(result)
		require.NoError(t, err)
		t.Log(string(encoded))
	default:
		t.Fatal("fixture action must be prepare or reconcile")
	}
}
