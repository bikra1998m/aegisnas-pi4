package integrations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

func TestPushControllerStatePostsExpectedPayload(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_TOKEN"
	t.Setenv(tokenEnv, "controller-secret")

	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "Bearer controller-secret", r.Header.Get("Authorization"))
		assert.Equal(t, "generic", r.Header.Get("X-AegisNAS-Controller-Platform"))
		assert.Equal(t, "push-config", r.Header.Get("X-AegisNAS-Sync-Mode"))
		assert.Equal(t, "generic-rest", r.Header.Get("X-AegisNAS-Controller-Adapter"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &payload))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"summary":"Generic controller accepted sync.","warnings":["staged-only"]}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Mode = "two-nic"
	cfg.Deployment.Profile = "enterprise"
	cfg.Deployment.Form = "virtual"
	cfg.Portal.Enabled = true
	cfg.Portal.Port = 8081
	cfg.Portal.ListenIP = "192.168.50.1"
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Radius.DynamicAuth.Port = 3799
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "generic"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "branch-lab"

	result, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "generic-rest", result.Adapter)
	assert.Equal(t, "bearer", result.AuthScheme)
	assert.Equal(t, http.StatusText(http.StatusAccepted), strings.TrimPrefix(result.ResponseStatus, "202 "))
	assert.Equal(t, "Generic controller accepted sync.", result.ResponseSummary)
	assert.Equal(t, 1, result.WarningCount)
	assert.Equal(t, "branch-lab", payload["controller"].(map[string]any)["site"])
	assert.Equal(t, "192.168.50.1", payload["portal"].(map[string]any)["listen_ip"])
}

func TestPushControllerStateUsesJuniperMistAdapter(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_TOKEN_MIST"
	t.Setenv(tokenEnv, "controller-secret")

	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/sites/branch-lab/aegisnas/sync", r.URL.Path)
		assert.Equal(t, "Token controller-secret", r.Header.Get("Authorization"))
		assert.Equal(t, "juniper-mist", r.Header.Get("X-AegisNAS-Controller-Platform"))
		assert.Equal(t, "juniper-mist", r.Header.Get("X-AegisNAS-Controller-Adapter"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &payload))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"summary":"Mist site staged.","site_id":"branch-lab"}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Portal.Enabled = true
	cfg.Portal.ListenIP = "192.168.50.1"
	cfg.Portal.Port = 8081
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Radius.DynamicAuth.Port = 3799
	cfg.Wireless.SSIDs = []config.SSIDConfig{{Name: "Guest", AuthMode: "wpa2-enterprise", VLAN: 20, PortalProfile: "guest"}}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "juniper-mist"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "branch-lab"

	result, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "juniper-mist", result.Adapter)
	assert.Equal(t, "token", result.AuthScheme)
	assert.Equal(t, "branch-lab", payload["site_id"])
	assert.Equal(t, float64(1812), payload["radius_config"].(map[string]any)["auth_port"])
	wlans := payload["wlan_overrides"].([]any)
	require.Len(t, wlans, 1)
	assert.Equal(t, "Guest", wlans[0].(map[string]any)["name"])
	assert.Equal(t, "branch-lab", result.ResponseDetails["response_scope"])
}

func TestPushControllerStateUsesCiscoAdapter(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_TOKEN_CISCO"
	t.Setenv(tokenEnv, "controller-secret")

	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/aegisnas/sites/branch-lab/sync", r.URL.Path)
		assert.Equal(t, "Bearer controller-secret", r.Header.Get("Authorization"))
		assert.Equal(t, "cisco-ise", r.Header.Get("X-AegisNAS-Controller-Adapter"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &payload))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Deployment.Profile = "branch"
	cfg.Portal.Enabled = true
	cfg.Portal.ListenIP = "192.168.50.1"
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Radius.DynamicAuth.Port = 3799
	cfg.Wireless.SSIDs = []config.SSIDConfig{{Name: "Guest", AuthMode: "captive-portal", VLAN: 30}}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "cisco"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "branch-lab"

	result, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "cisco-ise", result.Adapter)
	assert.Equal(t, "branch-lab", payload["site"])
	aaa := payload["aaa"].(map[string]any)
	servers := aaa["radius_servers"].([]any)
	require.Len(t, servers, 1)
	assert.Equal(t, float64(1812), servers[0].(map[string]any)["auth_port"])
	ssids := payload["ssid_policies"].([]any)
	require.Len(t, ssids, 1)
	assert.Equal(t, "Guest", ssids[0].(map[string]any)["name"])
}

func TestPushControllerStateRequiresToken(t *testing.T) {
	cfg := &config.Config{}
	cfg.Integrations.Controller.Endpoint = "https://example.invalid"
	cfg.Integrations.Controller.APITokenEnv = "AEGIS_MISSING_TOKEN"
	_, err := pushControllerState(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AEGIS_MISSING_TOKEN")
}

func TestStartControllerAutomationTracksRuntimeCounters(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_TOKEN_RUNTIME"
	t.Setenv(tokenEnv, "controller-secret")

	tmpfile, err := os.CreateTemp("", "controller-runtime-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "generic"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "branch-lab"

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		StartControllerAutomation(ctx, cfg, zap.NewNop())
	}()

	require.Eventually(t, func() bool {
		status, err := db.GetRuntimeStatus(ControllerComponent())
		if err != nil || status == nil || status.Status != "ok" {
			return false
		}
		return int64ControllerDetail(status.Details, "sync_count") >= 1 &&
			int64ControllerDetail(status.Details, "success_count") >= 1 &&
			int64ControllerDetail(status.Details, "failure_count") == 0
	}, 2*time.Second, 50*time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("controller automation did not stop after context cancellation")
	}
}
