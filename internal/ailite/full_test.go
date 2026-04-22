package ailite

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

func TestParseFullAIRecommendations(t *testing.T) {
	recs, err := parseFullAIRecommendations("```json\n{\"recommendations\":[{\"severity\":\"warning\",\"confidence\":0.8,\"title\":\"Tune AAA probes\",\"description\":\"Probe failures increased.\",\"remediation\":\"Check upstream health.\"}]}\n```")
	require.NoError(t, err)
	require.Len(t, recs, 1)
	assert.Equal(t, "Tune AAA probes", recs[0].Title)
	assert.Equal(t, 0.8, recs[0].Confidence)
}

func TestChatCompletionsURL(t *testing.T) {
	tests := map[string]string{
		"https://api.example.net":                         "https://api.example.net/v1/chat/completions",
		"https://api.example.net/v1":                      "https://api.example.net/v1/chat/completions",
		"https://api.example.net/v1/":                     "https://api.example.net/v1/chat/completions",
		"https://api.example.net/v1/chat/completions":     "https://api.example.net/v1/chat/completions",
		"https://api.example.net/custom/chat/completions": "https://api.example.net/custom/chat/completions",
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, want, chatCompletionsURL(input))
		})
	}
}

func TestRunFullAIAnalysisStoresRecommendation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "aegis.db")
	require.NoError(t, db.Init(dbPath))
	t.Cleanup(func() { db.Close() })
	require.NoError(t, db.Migrate())

	t.Setenv("AEGIS_AI_TEST_KEY", "secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
		var payload map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		assert.Equal(t, "ops-model", payload["model"])
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]any{
						"content": `{"recommendations":[{"severity":"critical","confidence":0.93,"title":"Investigate repeated portal failures","description":"The portal path has repeated failures in the recent window.","remediation":"Review portal logs and upstream AAA health before expanding rollout."}]}`,
					},
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	cfg := &config.Config{
		Mode: "two-nic",
		Deployment: config.DeploymentConfig{
			Profile: "enterprise",
			Form:    "physical",
			Hardware: config.DeploymentHardwareConfig{
				MemoryMB: 16384,
				CPUCores: 8,
			},
		},
		WAN:      config.InterfaceConfig{Name: "eth0"},
		LAN:      config.InterfaceConfig{Name: "eth1", Address: "192.168.50.1/24"},
		Database: config.DatabaseConfig{Path: dbPath},
		Health:   config.HealthConfig{Port: 8080},
		Radius: config.RadiusConfig{
			AuthPort:              1812,
			AcctPort:              1813,
			MaxSessions:           4096,
			RequestTimeoutSeconds: 5,
			InterimUpdateSeconds:  300,
			DynamicAuth:           config.DynamicAuthConfig{Enabled: true, Port: 3799},
			Upstream:              config.RadiusUpstreamConfig{StatusCheck: "status-server", PoolStrategy: "fail-over"},
		},
		Portal: config.PortalConfig{Enabled: true, RadiusAuth: true, LocalFallback: true},
		AILite: config.AILiteConfig{
			Enabled:               true,
			Mode:                  "full",
			Provider:              "openai-compatible",
			Endpoint:              server.URL,
			Model:                 "ops-model",
			APIKeyEnv:             "AEGIS_AI_TEST_KEY",
			RequestTimeoutSeconds: 5,
			MaxInputEvents:        50,
		},
		Telemetry: config.TelemetryConfig{Enabled: true, PrometheusPort: 9090},
	}

	analyzer, err := NewAnalyzer(cfg, zap.NewNop())
	require.NoError(t, err)
	analyzer.runFullAIAnalysis()

	var count int
	require.NoError(t, db.DB.QueryRow(`SELECT COUNT(*) FROM ai_recommendations WHERE source = ? AND title = ?`, fullAIComponent, "Investigate repeated portal failures").Scan(&count))
	assert.Equal(t, 1, count)
}
