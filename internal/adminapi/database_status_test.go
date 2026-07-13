package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetDatabaseStatusRedactsDSN(t *testing.T) {
	file, err := os.CreateTemp("", "database-status-*.db")
	require.NoError(t, err)
	path := file.Name()
	require.NoError(t, file.Close())
	require.NoError(t, db.Init(path))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() { _ = db.Close(); _ = os.Remove(path) })

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Backend:                      "postgres",
			DSNRef:                       "env:AEGIS_SECRET_POSTGRES_DSN",
			SSLMode:                      "verify-full",
			MaxOpenConns:                 20,
			MaxIdleConns:                 5,
			ProductionRequireTLS:         true,
			StatementTimeoutMilliseconds: 30000,
		},
	}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, config.WriteFile(configPath, cfg))
	_, err = config.Load(configPath)
	require.NoError(t, err)

	db.SetActiveConnectionInfoForTest(db.ConnectionInfo{
		Backend:        "postgres",
		Driver:         "aegis-pgx",
		Dialect:        "postgres",
		DSNRefSet:      true,
		DSNFingerprint: "7f83b1657ff1fc53b92dc18148a1d65dfa135249c5f95bc6b708f3f7ff3478a",
		SSLMode:        "verify-full",
		TLSRequired:    true,
	})
	t.Cleanup(func() { db.SetActiveConnectionInfoForTest(db.ConnectionInfo{}) })

	recorder := httptest.NewRecorder()
	HandleGetDatabaseStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/system/database", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.NotContains(t, recorder.Body.String(), "postgres://")
	assert.NotContains(t, recorder.Body.String(), "AEGIS_SECRET_POSTGRES_DSN")

	var payload struct {
		Active struct {
			Backend        string `json:"backend"`
			DSNRefSet      bool   `json:"dsn_ref_set"`
			DSNFingerprint string `json:"dsn_fingerprint"`
		} `json:"active"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
	assert.Equal(t, "postgres", payload.Active.Backend)
	assert.True(t, payload.Active.DSNRefSet)
	assert.NotEmpty(t, payload.Active.DSNFingerprint)
}
