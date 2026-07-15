package adminapi

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestHandleGetRadSecCredentialsRedactsTLSPSKSecretRef(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Mode:      "two-nic",
		WAN:       config.InterfaceConfig{Name: "eth0"},
		LAN:       config.InterfaceConfig{Name: "eth1"},
		Database:  config.DatabaseConfig{Path: filepath.Join(dir, "data.db")},
		Health:    config.HealthConfig{Port: 8080},
		Telemetry: config.TelemetryConfig{PrometheusPort: 9090},
		Radius: config.RadiusConfig{
			AuthPort: 1812, AcctPort: 1813, RequestTimeoutSeconds: 5,
			Upstream: config.RadiusUpstreamConfig{Servers: []config.RadiusHomeServer{{Name: "psk-aaa", Address: "203.0.113.30", Transport: "radsec", RadSec: config.RadiusRadSecPeerConfig{
				Port: 2083, ServerName: "aaa-psk.example.net", TLSMinVersion: "1.3", TLSMaxVersion: "1.3",
				CipherList: "DEFAULT@SECLEVEL=2", RadiusV11: "forbid",
				PSK: config.RadiusRadSecPSKConfig{Enabled: true, Identity: "aegisnas-psk", SecretRef: "env:RADSEC_PSK_CURRENT"},
			}}}},
		},
	}
	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, config.WriteFile(configPath, cfg))
	_, err := config.Load(configPath)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	HandleGetRadSecCredentials(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/system/radsec-credentials", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `"mode":"tls-psk"`)
	assert.Contains(t, recorder.Body.String(), `"psk_secret_ref_set":true`)
	assert.NotContains(t, recorder.Body.String(), "RADSEC_PSK_CURRENT")
}
