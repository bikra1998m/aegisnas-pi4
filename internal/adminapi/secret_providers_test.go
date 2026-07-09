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

func TestHandleGetSecretProvidersRedactsValuesAndIncludesDBRefs(t *testing.T) {
	file, err := os.CreateTemp("", "secret-providers-*.db")
	require.NoError(t, err)
	path := file.Name()
	require.NoError(t, file.Close())
	require.NoError(t, db.Init(path))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() { _ = db.Close(); _ = os.Remove(path) })
	t.Setenv("AEGIS_RADIUS_SHARED_SECRET", "do-not-return")
	t.Setenv("AEGIS_DB_SECRET", "also-do-not-return")

	_, err = db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, secret_ref, nas_type, transport, enabled)
		VALUES ('ref-ap', '192.0.2.10', '', 'env:AEGIS_DB_SECRET', 'aruba', 'udp', 1)`)
	require.NoError(t, err)

	cfg := &config.Config{
		Security: config.SecurityConfig{Secrets: config.SecretProviderConfig{Enabled: true, Providers: []string{"env"}, AllowInline: true, ProductionRequireReferences: true, MaxSecretBytes: 128}},
		Radius:   config.RadiusConfig{SecretRef: "env:AEGIS_RADIUS_SHARED_SECRET"},
	}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, config.WriteFile(configPath, cfg))
	_, err = config.Load(configPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = config.Load(filepath.Join("..", "..", "configs", "config.example.yaml"))
	})

	recorder := httptest.NewRecorder()
	HandleGetSecretProviders(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/system/secret-providers", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.NotContains(t, recorder.Body.String(), "do-not-return")
	assert.NotContains(t, recorder.Body.String(), "also-do-not-return")

	var payload struct {
		Status  string `json:"status"`
		Summary struct {
			ReferenceCount int `json:"reference_count"`
			InlineCount    int `json:"inline_count"`
		} `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
	assert.Equal(t, "ready", payload.Status)
	assert.Equal(t, 2, payload.Summary.ReferenceCount)
	assert.Equal(t, 0, payload.Summary.InlineCount)
}
