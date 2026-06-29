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
	require.NoError(t, db.UpsertRuntimeStatus(integrations.ControllerComponent(), "degraded", "Controller sync completed with 2 drift item(s).", map[string]any{
		"sync_count":          3,
		"success_count":       3,
		"failure_count":       0,
		"last_duration_ms":    150,
		"drift_detected":      true,
		"drift_count":         2,
		"controller_health":   "degraded",
		"compatibility_score": 82,
	}))
	require.NoError(t, db.RecordVendorObservability(db.VendorObservabilityDelta{
		VendorKey:                 "aruba",
		NASType:                   "aruba-ap",
		AuthSuccessDelta:          5,
		UnsupportedAttributeDelta: 1,
		Message:                   "unsupported Aruba VSA type 99",
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
			Status  string         `json:"status"`
			Details map[string]any `json:"details"`
		} `json:"controller_sync"`
		VendorObservability struct {
			Status  string `json:"status"`
			Summary struct {
				TotalVendors              int `json:"total_vendors"`
				UnsupportedAttributeCount int `json:"unsupported_attribute_count"`
			} `json:"summary"`
		} `json:"vendor_observability"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, 1, payload.ApplyStats.ApplySuccessCount)
	assert.Equal(t, 1, payload.LeaseTrends.UniqueMACsWindow)
	assert.Equal(t, "degraded", payload.ControllerSync.Status)
	assert.Equal(t, true, payload.ControllerSync.Details["drift_detected"])
	assert.Equal(t, float64(2), payload.ControllerSync.Details["drift_count"])
	assert.Equal(t, "degraded", payload.ControllerSync.Details["controller_health"])
	assert.Equal(t, float64(82), payload.ControllerSync.Details["compatibility_score"])
	assert.Equal(t, "warned", payload.VendorObservability.Status)
	assert.Equal(t, 1, payload.VendorObservability.Summary.TotalVendors)
	assert.Equal(t, 1, payload.VendorObservability.Summary.UnsupportedAttributeCount)
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
