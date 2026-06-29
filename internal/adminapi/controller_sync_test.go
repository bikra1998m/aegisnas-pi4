package adminapi

import (
	"bytes"
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

func TestControllerSyncPreviewAndManualPull(t *testing.T) {
	const tokenEnv = "AEGIS_ADMIN_CONTROLLER_SYNC_TOKEN"
	t.Setenv(tokenEnv, "controller-secret")
	_ = prepareSupportBundleTestConfig(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/proxy/network/api/s/default/aegisnas/state", r.URL.Path)
		assert.Equal(t, "pull", r.Header.Get("X-AegisNAS-Controller-Operation"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"summary":"UniFi state loaded.","observed_state_hash":"stale-controller-state","health":"healthy"}`))
	}))
	defer server.Close()

	cfg := config.Get()
	require.NotNil(t, cfg)
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "unifi"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "monitor"
	cfg.Integrations.Controller.Site = "default"

	previewReq := httptest.NewRequest(http.MethodGet, "/api/v1/system/controller-sync/preview?operation=pull", nil)
	previewRec := httptest.NewRecorder()
	HandlePreviewControllerSync(previewRec, previewReq)
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var preview struct {
		Preview struct {
			Operation string `json:"operation"`
			Method    string `json:"method"`
			TargetURL string `json:"target_url"`
		} `json:"preview"`
		PushConfirmation string `json:"push_confirmation"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &preview))
	assert.Equal(t, "pull", preview.Preview.Operation)
	assert.Equal(t, http.MethodGet, preview.Preview.Method)
	assert.Contains(t, preview.Preview.TargetURL, "/aegisnas/state")
	assert.Equal(t, controllerPushConfirmation, preview.PushConfirmation)

	runReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/controller-sync", bytes.NewBufferString(`{"operation":"pull"}`))
	runRec := httptest.NewRecorder()
	HandleRunControllerSync(runRec, runReq)
	require.Equal(t, http.StatusOK, runRec.Code, runRec.Body.String())
	var response struct {
		Status string `json:"status"`
		Result struct {
			DriftDetected bool `json:"drift_detected"`
			DriftCount    int  `json:"drift_count"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(runRec.Body.Bytes(), &response))
	assert.Equal(t, "degraded", response.Status)
	assert.True(t, response.Result.DriftDetected)
	assert.Equal(t, 1, response.Result.DriftCount)

	history, err := db.ListIntegrationHistory(integrations.ControllerComponent(), 10)
	require.NoError(t, err)
	require.NotEmpty(t, history)
	assert.Equal(t, "degraded", history[0].Status)
	assert.Contains(t, history[0].Summary, "detected policy drift")

	runtime, err := db.GetRuntimeStatus(integrations.ControllerComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.EqualValues(t, 1, runtime.Details["sync_count"])
	assert.EqualValues(t, 1, runtime.Details["failure_count"])
}

func TestControllerManualPushRequiresConfirmation(t *testing.T) {
	const tokenEnv = "AEGIS_ADMIN_CONTROLLER_PUSH_TOKEN"
	t.Setenv(tokenEnv, "controller-secret")
	_ = prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "generic"
	cfg.Integrations.Controller.Endpoint = "https://controller.example.test/sync"
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "push-config"

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/controller-sync", bytes.NewBufferString(`{"operation":"push"}`))
	rec := httptest.NewRecorder()
	HandleRunControllerSync(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), controllerPushConfirmation)
}
