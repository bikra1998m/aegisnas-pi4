package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestRunNetworkExportCycleAndListNetworkExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "network-exports")
	cfg.Telemetry.NetworkExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	require.NoError(t, db.RecordNetworkApplyHistory("apply", "success", "all validation checks passed", "backup-1", "", "tester", map[string]any{"healthy": true}))
	require.NoError(t, db.StoreDHCPLeaseObservations(time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC), []db.DHCPLeaseObservation{{
		MAC:              "aa:bb:cc:dd:ee:ff",
		IP:               "192.168.50.10",
		Hostname:         "lab-client",
		ClientID:         "client-1",
		Reservation:      true,
		Expired:          false,
		ExpiresAt:        "2026-05-23T22:00:00Z",
		RemainingSeconds: 43200,
	}}))

	now := time.Date(2026, 5, 23, 11, 45, 0, 0, time.UTC)
	origNow := networkExportNow
	networkExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		networkExportNow = origNow
	})

	runNetworkExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(networkExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/network-exports", nil)
	rec := httptest.NewRecorder()
	HandleListNetworkExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus       `json:"runtime"`
		Exports []NetworkExportArtifact `json:"exports"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Runtime)
	require.Len(t, payload.Exports, 4)
	assert.Equal(t, "ok", payload.Runtime.Status)

	formats := make([]string, 0, len(payload.Exports))
	kinds := make([]string, 0, len(payload.Exports))
	for _, artifact := range payload.Exports {
		formats = append(formats, artifact.Format)
		kinds = append(kinds, artifact.Kind)
	}
	assert.ElementsMatch(t, []string{"csv", "csv", "json", "json"}, formats)
	assert.ElementsMatch(t, []string{"network_apply_history", "network_apply_history", "dhcp_lease_history", "dhcp_lease_history"}, kinds)
}

func TestHandleDownloadNetworkExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "network-export-downloads")
	cfg.Telemetry.NetworkExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	require.NoError(t, db.RecordNetworkApplyHistory("apply", "success", "all validation checks passed", "backup-1", "", "tester", map[string]any{"healthy": true}))
	require.NoError(t, db.StoreDHCPLeaseObservations(time.Date(2026, 5, 23, 10, 5, 0, 0, time.UTC), []db.DHCPLeaseObservation{{
		MAC:              "aa:bb:cc:dd:ee:11",
		IP:               "192.168.50.20",
		Hostname:         "printer",
		ClientID:         "printer-1",
		Reservation:      false,
		Expired:          false,
		ExpiresAt:        "2026-05-23T22:05:00Z",
		RemainingSeconds: 43000,
	}}))

	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	origNow := networkExportNow
	networkExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		networkExportNow = origNow
	})

	runNetworkExportCycle(context.Background(), cfg)

	artifacts, err := listNetworkExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 2)

	var leaseArtifact NetworkExportArtifact
	for _, artifact := range artifacts {
		if artifact.Kind == "dhcp_lease_history" {
			leaseArtifact = artifact
			break
		}
	}
	require.NotEmpty(t, leaseArtifact.Name)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/network-exports/download?name="+leaseArtifact.Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadNetworkExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), leaseArtifact.Name)
	assert.Contains(t, rec.Body.String(), `"printer"`)
}
