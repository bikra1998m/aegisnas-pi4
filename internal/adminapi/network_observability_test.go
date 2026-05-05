package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/integrations"
)

func TestHandleGetNetworkObservability(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "network-observability-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())

	observedAt := time.Now().UTC()
	require.NoError(t, db.RecordNetworkApplyHistory("apply", "success", "all validation checks passed", "backup-1", "", "tester", nil))
	require.NoError(t, db.StoreDHCPLeaseObservations(observedAt, []db.DHCPLeaseObservation{{
		MAC:              "aa:bb:cc:dd:ee:ff",
		IP:               "192.168.50.10",
		Hostname:         "lab-client",
		Reservation:      true,
		Expired:          false,
		ExpiresAt:        observedAt.Add(time.Hour).Format(time.RFC3339),
		RemainingSeconds: 3600,
	}}))
	require.NoError(t, db.UpsertRuntimeStatus(integrations.ControllerComponent(), "ok", "Controller sync healthy.", map[string]any{
		"sync_count":       3,
		"success_count":    3,
		"failure_count":    0,
		"last_duration_ms": 150,
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/network-observability", nil)
	rec := httptest.NewRecorder()
	HandleGetNetworkObservability(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		ApplyStats struct {
			ApplySuccessCount int `json:"apply_success_count"`
		} `json:"apply_stats"`
		LeaseTrends struct {
			UniqueMACsWindow int `json:"unique_macs_window"`
		} `json:"lease_trends"`
		ControllerSync struct {
			Status string `json:"status"`
		} `json:"controller_sync"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, 1, payload.ApplyStats.ApplySuccessCount)
	assert.Equal(t, 1, payload.LeaseTrends.UniqueMACsWindow)
	assert.Equal(t, "ok", payload.ControllerSync.Status)
}

func TestHandleExportNetworkApplyHistoryCSV(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "network-observability-export-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())
	require.NoError(t, db.RecordNetworkApplyHistory("apply", "success", "all validation checks passed", "backup-1", "", "tester", map[string]any{"healthy": true}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/network-apply-history/export?format=csv", nil)
	rec := httptest.NewRecorder()
	HandleExportNetworkApplyHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, rec.Body.String(), "id,created_at,action,status,summary")
	assert.Contains(t, rec.Body.String(), "backup-1")
}

func TestHandleExportDHCPLeaseHistoryCSV(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "lease-observability-export-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())
	observedAt := time.Now().UTC()
	require.NoError(t, db.StoreDHCPLeaseObservations(observedAt, []db.DHCPLeaseObservation{{
		MAC:              "aa:bb:cc:dd:ee:ff",
		IP:               "192.168.50.10",
		Hostname:         "lab-client",
		Reservation:      true,
		Expired:          false,
		ExpiresAt:        observedAt.Add(time.Hour).Format(time.RFC3339),
		RemainingSeconds: 3600,
	}}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dhcp-lease-history/export?format=csv", nil)
	rec := httptest.NewRecorder()
	HandleExportDHCPLeaseHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/csv")
	assert.True(t, strings.Contains(rec.Body.String(), "aa:bb:cc:dd:ee:ff"))
}
