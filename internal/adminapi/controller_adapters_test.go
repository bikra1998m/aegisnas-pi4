package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/integrations"
)

func TestHandleGetControllerAdapters(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_ADAPTER_TOKEN"
	t.Setenv(tokenEnv, "secret")
	_ = prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "ubnt"
	cfg.Integrations.Controller.Endpoint = "https://unifi.example.test"
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "default"
	require.NoError(t, db.UpsertRuntimeStatus(integrations.ControllerComponent(), "ok", "Controller sync healthy.", map[string]any{
		"adapter":       "unifi-network",
		"sync_count":    3,
		"success_count": 3,
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/controller-adapters", nil)
	rec := httptest.NewRecorder()

	HandleGetControllerAdapters(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Adapters []struct {
			Platform           string   `json:"platform"`
			Adapter            string   `json:"adapter"`
			RequiresSite       bool     `json:"requires_site"`
			SupportedSyncModes []string `json:"supported_sync_modes"`
			SiteProfiles       bool     `json:"site_profiles"`
		} `json:"adapters"`
		Configured struct {
			Enabled        bool   `json:"enabled"`
			Platform       string `json:"platform"`
			Normalized     string `json:"normalized_platform"`
			Adapter        string `json:"adapter"`
			Ready          bool   `json:"ready"`
			TokenPresent   bool   `json:"token_present"`
			SiteRequired   bool   `json:"site_required"`
			SiteConfigured bool   `json:"site_configured"`
			Selected       struct {
				Platform     string `json:"platform"`
				SiteProfiles bool   `json:"site_profiles"`
			} `json:"selected"`
		} `json:"configured"`
		Runtime struct {
			Status  string         `json:"status"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"runtime"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))

	require.Len(t, payload.Adapters, 8)
	assert.True(t, controllerAdapterPayloadContains(payload.Adapters, "cisco"))
	assert.True(t, controllerAdapterPayloadContains(payload.Adapters, "unifi"))
	assert.Equal(t, "ubnt", payload.Configured.Platform)
	assert.Equal(t, "unifi", payload.Configured.Normalized)
	assert.Equal(t, "unifi-network", payload.Configured.Adapter)
	assert.True(t, payload.Configured.Ready)
	assert.True(t, payload.Configured.TokenPresent)
	assert.True(t, payload.Configured.SiteRequired)
	assert.True(t, payload.Configured.SiteConfigured)
	assert.True(t, payload.Configured.Selected.SiteProfiles)
	assert.Equal(t, "ok", payload.Runtime.Status)
	assert.Equal(t, "Controller sync healthy.", payload.Runtime.Message)
	assert.Equal(t, "unifi-network", payload.Runtime.Details["adapter"])
}

func TestBuildControllerAdapterConfiguredStateReportsWarnings(t *testing.T) {
	state := buildControllerAdapterConfiguredState(&config.Config{
		Integrations: config.IntegrationsConfig{
			Controller: config.ControllerConfig{
				Enabled:     true,
				Platform:    "aruba",
				SyncMode:    "push-config",
				APITokenEnv: "AEGIS_MISSING_CONTROLLER_TOKEN",
			},
		},
	})

	assert.Equal(t, "aruba", state.Normalized)
	assert.Equal(t, "aruba-central", state.Adapter)
	assert.True(t, state.SiteRequired)
	assert.False(t, state.SiteConfigured)
	assert.False(t, state.EndpointSet)
	assert.False(t, state.TokenPresent)
	assert.False(t, state.Ready)
	assert.Contains(t, state.ReadinessWarnings, "controller endpoint is not configured")
	assert.Contains(t, state.ReadinessWarnings, "controller API token environment variable is configured but not present in the process environment")
	assert.Contains(t, state.ReadinessWarnings, "selected controller platform requires a site, zone, or network identifier")
}

func TestBuildControllerAdapterConfiguredStateUsesCiscoBasicCredentials(t *testing.T) {
	const usernameEnv = "AEGIS_TEST_ISE_USERNAME"
	const passwordEnv = "AEGIS_TEST_ISE_PASSWORD"
	t.Setenv(usernameEnv, "ers-admin")
	t.Setenv(passwordEnv, "secret")

	state := buildControllerAdapterConfiguredState(&config.Config{
		Integrations: config.IntegrationsConfig{
			Controller: config.ControllerConfig{
				Enabled: true, Platform: "cisco", Endpoint: "https://ise.example.test:9060",
				APIUsernameEnv: usernameEnv, APIPasswordEnv: passwordEnv, SyncMode: "monitor", Site: "branch-lab",
			},
		},
	})

	assert.True(t, state.UsernamePresent)
	assert.True(t, state.PasswordPresent)
	assert.True(t, state.Ready)
	assert.Equal(t, "basic", state.Selected.AuthScheme)
	assert.Equal(t, "cisco-ise-ers", state.Adapter)
}

func controllerAdapterPayloadContains(adapters []struct {
	Platform           string   `json:"platform"`
	Adapter            string   `json:"adapter"`
	RequiresSite       bool     `json:"requires_site"`
	SupportedSyncModes []string `json:"supported_sync_modes"`
	SiteProfiles       bool     `json:"site_profiles"`
}, platform string) bool {
	for _, adapter := range adapters {
		if adapter.Platform == platform {
			return true
		}
	}
	return false
}
