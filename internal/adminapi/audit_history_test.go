package adminapi

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleListAuditHistory(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	now := time.Date(2026, 5, 21, 9, 0, 0, 0, time.UTC)
	_, err := db.DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
		now, "ops-admin", "download_support_bundle", "bundle", "downloaded", "192.168.50.10")
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
		now.Add(time.Minute), "guest-admin", "guest_registration_approved", "guest-1", "approved", "192.168.50.11")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/audit-history?action_prefix=download_", nil)
	rec := httptest.NewRecorder()
	HandleListAuditHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		ActionPrefix string                  `json:"action_prefix"`
		Count        int                     `json:"count"`
		History      []db.AuditHistoryRecord `json:"history"`
		Stats        db.AuditHistoryStats    `json:"stats"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "download_", payload.ActionPrefix)
	assert.Len(t, payload.History, 1)
	assert.Equal(t, "download_support_bundle", payload.History[0].Action)
	assert.Equal(t, 2, payload.Stats.TotalRecords)
}

func TestHandleExportAuditHistoryCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	_, err := db.DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
		time.Date(2026, 5, 21, 9, 0, 0, 0, time.UTC), "ops-admin", "apply_network_services", "config.yaml", "applied", "192.168.50.10")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/audit-history/export?format=csv", nil)
	rec := httptest.NewRecorder()
	HandleExportAuditHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))

	reader := csv.NewReader(strings.NewReader(rec.Body.String()))
	rows, err := reader.ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "action", rows[0][3])
	assert.Equal(t, "apply_network_services", rows[1][3])
}
