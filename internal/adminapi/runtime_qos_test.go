package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestRuntimeQoSAPIPreviewStatusHistoryReadinessProfilesAndSupportBundle(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)
	_, err := db.DB.Exec(`INSERT INTO bandwidth_profiles (name, download_rate_kbps, upload_rate_kbps, burst_kb)
		VALUES (?, ?, ?, ?)`, "voice", 2048, 1024, 128)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO sessions (id, username, ip, bandwidth_profile, start_time)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`, "s-voice", "alice", "192.0.2.80", "voice")
	require.NoError(t, err)

	enabled := true
	priority := 1
	dscp := 46
	body, err := json.Marshal(qosSchedulerProfileRequest{
		Enabled:              &enabled,
		Scheduler:            "htb",
		Priority:             &priority,
		DSCPMark:             &dscp,
		DownloadCeilRateKbps: 3000,
		UploadCeilRateKbps:   1500,
		BurstKB:              128,
		CBurstKB:             128,
		Metadata:             map[string]any{"owner": "ops"},
	})
	require.NoError(t, err)
	upsertRec := httptest.NewRecorder()
	HandleUpsertQoSSchedulerProfile(upsertRec, requestWithChiParam(httptest.NewRequest(http.MethodPut, "/api/v1/system/qos-scheduler/profiles/voice", bytes.NewReader(body)), "name", "voice"))
	require.Equal(t, http.StatusOK, upsertRec.Code, upsertRec.Body.String())

	profilesRec := httptest.NewRecorder()
	HandleListQoSSchedulerProfiles(profilesRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/qos-scheduler/profiles", nil))
	require.Equal(t, http.StatusOK, profilesRec.Code, profilesRec.Body.String())
	assert.Contains(t, profilesRec.Body.String(), `"profile_name":"voice"`)
	assert.Contains(t, profilesRec.Body.String(), `"dscp_mark":46`)

	previewRec := httptest.NewRecorder()
	HandlePreviewRuntimeQoS(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/qos-scheduler/preview", bytes.NewBufferString(`{}`)))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Plan    struct {
			Status  string `json:"status"`
			Summary struct {
				ProfileCount   int `json:"profile_count"`
				ClassCount     int `json:"class_count"`
				ShapedSessions int `json:"shaped_sessions"`
				CommandCount   int `json:"command_count"`
			} `json:"summary"`
			Sessions []struct {
				DownloadClassID string `json:"download_class_id"`
				UploadClassID   string `json:"upload_class_id"`
			} `json:"sessions"`
		} `json:"plan"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "ready", previewPayload.Plan.Status)
	assert.Equal(t, 1, previewPayload.Plan.Summary.ProfileCount)
	assert.Equal(t, 4, previewPayload.Plan.Summary.ClassCount)
	assert.Equal(t, 1, previewPayload.Plan.Summary.ShapedSessions)
	assert.NotZero(t, previewPayload.Plan.Summary.CommandCount)
	require.Len(t, previewPayload.Plan.Sessions, 1)
	assert.Equal(t, "1:1000", previewPayload.Plan.Sessions[0].DownloadClassID)
	assert.Equal(t, "2:1000", previewPayload.Plan.Sessions[0].UploadClassID)

	statusRec := httptest.NewRecorder()
	HandleGetRuntimeQoS(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/qos-scheduler", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"classes"`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListRuntimeQoSHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/qos-scheduler/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "hierarchical_qos_scheduler"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/qos-scheduler",
		"/api/v1/system/qos-scheduler/preview",
		"/api/v1/system/qos-scheduler/apply",
		"/api/v1/system/qos-scheduler/rollback",
		"/api/v1/system/qos-scheduler/history",
		"/api/v1/system/qos-scheduler/profiles",
		"/api/v1/system/qos-scheduler/profiles/{name}",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/qos-scheduler.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/qos-scheduler-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestRuntimeQoSRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/qos-scheduler"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/qos-scheduler/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/qos-scheduler/history"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/qos-scheduler/profiles"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/qos-scheduler/apply"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/qos-scheduler/rollback"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "PUT", "/api/v1/system/qos-scheduler/profiles/voice"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/qos-scheduler/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/qos-scheduler/rollback"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "PUT", "/api/v1/system/qos-scheduler/profiles/voice"))
}

func requestWithChiParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func prepareRuntimeQoSAPITestRuntime(t *testing.T) {
	t.Helper()
	previousDB := db.DB
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
mode: two-nic
deployment:
  profile: enterprise
  form: virtual
  hardware:
    memory_mb: 8192
    cpu_cores: 4
    storage_gb: 64
wan:
  name: ens33
  dhcp: true
lan:
  name: ens37
  address: 192.168.50.1/24
policy:
  runtime_shaping_enabled: true
database:
  path: ":memory:"
radius:
  secret: radius-shared-secret
  dynamic_auth:
    enabled: true
    port: 3799
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
}
