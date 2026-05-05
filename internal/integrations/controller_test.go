package integrations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &payload))
		w.WriteHeader(http.StatusAccepted)
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

	require.NoError(t, pushControllerState(context.Background(), cfg))
	assert.Equal(t, "branch-lab", payload["controller"].(map[string]any)["site"])
	assert.Equal(t, "192.168.50.1", payload["portal"].(map[string]any)["listen_ip"])
}

func TestPushControllerStateRequiresToken(t *testing.T) {
	cfg := &config.Config{}
	cfg.Integrations.Controller.Endpoint = "https://example.invalid"
	cfg.Integrations.Controller.APITokenEnv = "AEGIS_MISSING_TOKEN"
	err := pushControllerState(context.Background(), cfg)
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
