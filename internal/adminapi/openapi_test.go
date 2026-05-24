package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGetOpenAPI(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	req := httptest.NewRequest(http.MethodGet, "https://appliance.example.test/api/v1/openapi.json", nil)
	rec := httptest.NewRecorder()

	HandleGetOpenAPI(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))

	assert.Equal(t, "3.1.0", payload["openapi"])

	info, ok := payload["info"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "AegisNAS Admin API", info["title"])

	paths, ok := payload["paths"].(map[string]any)
	require.True(t, ok)

	statusPath, ok := paths["/api/v1/system/status"].(map[string]any)
	require.True(t, ok)
	statusGet, ok := statusPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Read system runtime status", statusGet["summary"])
	assert.Contains(t, statusGet["x-aegisnas-roles"], "read_only")

	specPath, ok := paths["/api/v1/openapi.json"].(map[string]any)
	require.True(t, ok)
	specGet, ok := specPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "public", specGet["x-aegisnas-visibility"])

	diagnosticsPath, ok := paths["/api/v1/system/diagnostics-report/export"].(map[string]any)
	require.True(t, ok)
	diagnosticsGet, ok := diagnosticsPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Export diagnostics report", diagnosticsGet["summary"])
	assert.Contains(t, diagnosticsGet["x-aegisnas-roles"], "read_only")
	parameters, ok := diagnosticsGet["parameters"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, parameters)

	scheduledDiagnosticsPath, ok := paths["/api/v1/system/diagnostics-exports/download"].(map[string]any)
	require.True(t, ok)
	scheduledDiagnosticsGet, ok := scheduledDiagnosticsPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Download scheduled diagnostics export", scheduledDiagnosticsGet["summary"])

	integrationHistoryPath, ok := paths["/api/v1/system/integration-history/export"].(map[string]any)
	require.True(t, ok)
	integrationHistoryGet, ok := integrationHistoryPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Export integration automation history", integrationHistoryGet["summary"])

	scheduledIntegrationPath, ok := paths["/api/v1/system/integration-exports/download"].(map[string]any)
	require.True(t, ok)
	scheduledIntegrationGet, ok := scheduledIntegrationPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Download scheduled integration export", scheduledIntegrationGet["summary"])

	scheduledHAPath, ok := paths["/api/v1/system/ha/exports/download"].(map[string]any)
	require.True(t, ok)
	scheduledHAGet, ok := scheduledHAPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Download scheduled HA export", scheduledHAGet["summary"])

	scheduledNetworkPath, ok := paths["/api/v1/system/network-exports/download"].(map[string]any)
	require.True(t, ok)
	scheduledNetworkGet, ok := scheduledNetworkPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Download scheduled network export", scheduledNetworkGet["summary"])

	scheduledUpstreamAAAPath, ok := paths["/api/v1/system/upstream-aaa-exports/download"].(map[string]any)
	require.True(t, ok)
	scheduledUpstreamAAAGet, ok := scheduledUpstreamAAAPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Download scheduled upstream AAA export", scheduledUpstreamAAAGet["summary"])

	auditHistoryPath, ok := paths["/api/v1/system/audit-history/export"].(map[string]any)
	require.True(t, ok)
	auditHistoryGet, ok := auditHistoryPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Export audit history", auditHistoryGet["summary"])

	scheduledAuditPath, ok := paths["/api/v1/system/audit-exports/download"].(map[string]any)
	require.True(t, ok)
	scheduledAuditGet, ok := scheduledAuditPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Download scheduled audit export", scheduledAuditGet["summary"])

	components, ok := payload["components"].(map[string]any)
	require.True(t, ok)
	securitySchemes, ok := components["securitySchemes"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, securitySchemes, "bearerAuth")
}
