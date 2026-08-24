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

func TestSubscriberRouteExportAPIHistoryOpenAPIReadinessSupportBundleAndRBAC(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	cfg.Radius.RoutePolicy.Enabled = true
	cfg.Radius.RoutePolicy.DynamicRouting = config.RadiusDynamicRoutingConfig{
		Enabled:           true,
		ApplyEnabled:      true,
		Driver:            "file",
		ArtifactPath:      filepath.Join(t.TempDir(), "subscriber-routes.frr"),
		MaxExportedRoutes: 16,
		Dampening: config.RadiusRouteDampeningConfig{
			Enabled: false,
		},
		Protocols: []config.RadiusDynamicProtocolConfig{
			{
				Protocol:        "bgp",
				Enabled:         true,
				VRF:             "all",
				ASN:             64512,
				RouteMap:        "AEGISNAS-SUBSCRIBER",
				AddressFamilies: []string{"ipv4", "ipv6"},
				Communities:     []string{"no-export"},
				LocalPreference: 100,
			},
		},
	}

	_, err := db.RecordRoutePolicyEvent(db.RoutePolicyEventInput{
		Operation:       "compile",
		Status:          "compiled",
		Role:            "branch-vpn",
		SessionID:       "session-1",
		AcctSessionID:   "acct-1",
		VRF:             "corp",
		Owner:           "network-team",
		Revision:        "sha256:route",
		IPv4RouteCount:  1,
		AttributeCount:  2,
		Fingerprint:     "sha256:compiled",
		RequestJSON:     "{}",
		ResponseJSON:    "{}",
		DiagnosticsJSON: "[]",
		Actor:           "ops",
		Ownership: []db.RoutePolicyOwnershipInput{
			{Family: "ipv4", Destination: "10.80.0.0/16", Gateway: "192.0.2.1", Metric: 10, Tag: "65000", Source: "role"},
		},
	})
	require.NoError(t, err)

	previewRec := httptest.NewRecorder()
	HandlePreviewSubscriberRouteExport(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/subscriber-route-export/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Plan    struct {
			Status       string `json:"status"`
			ArtifactText string `json:"artifact_text"`
			Summary      struct {
				ExportedRoutes int `json:"exported_routes"`
				CommandCount   int `json:"command_count"`
			} `json:"summary"`
		} `json:"plan"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "ready", previewPayload.Plan.Status)
	assert.Equal(t, 1, previewPayload.Plan.Summary.ExportedRoutes)
	assert.NotZero(t, previewPayload.Plan.Summary.CommandCount)
	assert.Contains(t, previewPayload.Plan.ArtifactText, "router bgp 64512 vrf corp")

	applyRec := httptest.NewRecorder()
	HandleApplySubscriberRouteExport(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/subscriber-route-export/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)
	artifact, err := os.ReadFile(cfg.Radius.RoutePolicy.DynamicRouting.ArtifactPath)
	require.NoError(t, err)
	assert.Contains(t, string(artifact), "ip route vrf corp 10.80.0.0/16 192.0.2.1 10 tag 65000")

	statusRec := httptest.NewRecorder()
	HandleGetSubscriberRouteExport(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/subscriber-route-export", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), "subscriber-routes.frr")
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListSubscriberRouteExportHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/subscriber-route-export/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"total_events":2`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(cfg)
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "dynamic_subscriber_route_export"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), cfg)
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/subscriber-route-export",
		"/api/v1/system/subscriber-route-export/preview",
		"/api/v1/system/subscriber-route-export/apply",
		"/api/v1/system/subscriber-route-export/rollback",
		"/api/v1/system/subscriber-route-export/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/subscriber-route-export.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/subscriber-route-export-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/subscriber-route-export"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/subscriber-route-export/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/subscriber-route-export/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/subscriber-route-export/apply"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/subscriber-route-export/rollback"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/subscriber-route-export/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/subscriber-route-export/rollback"))
}
