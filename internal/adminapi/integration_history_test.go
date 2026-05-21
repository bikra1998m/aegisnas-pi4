package adminapi

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleListIntegrationHistory(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	require.NoError(t, db.RecordIntegrationHistory("controller_automation", "ok", "Controller sync completed.", map[string]any{"adapter": "cisco-ise"}))
	require.NoError(t, db.RecordIntegrationHistory("mdm_sync", "degraded", "MDM sync failed.", map[string]any{"provider": "intune"}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/integration-history?component=controller_automation", nil)
	rec := httptest.NewRecorder()
	HandleListIntegrationHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		Component string                        `json:"component"`
		Count     int                           `json:"count"`
		History   []db.IntegrationHistoryRecord `json:"history"`
		Stats     db.IntegrationHistoryStats    `json:"stats"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "controller_automation", payload.Component)
	assert.Len(t, payload.History, 1)
	assert.Equal(t, "controller_automation", payload.History[0].Component)
	assert.Equal(t, 2, payload.Stats.TotalRecords)
	assert.Equal(t, 1, payload.Stats.ControllerSuccessCount)
}

func TestHandleExportIntegrationHistoryCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	require.NoError(t, db.RecordIntegrationHistory("posture_checks", "ok", "Compliance webhook evaluation completed.", map[string]any{"provider": "workspace-one"}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/integration-history/export?format=csv&component=posture_checks", nil)
	rec := httptest.NewRecorder()
	HandleExportIntegrationHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-integration-history-posture_checks.csv")

	reader := csv.NewReader(strings.NewReader(rec.Body.String()))
	rows, err := reader.ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "component", rows[0][2])
	assert.Equal(t, "posture_checks", rows[1][2])
}

func TestHandleExportIntegrationHistoryRejectsUnsupportedFormat(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/integration-history/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportIntegrationHistory(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}
