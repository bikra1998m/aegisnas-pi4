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

func TestRunSessionAnalyticsExportCycleAndListSessionAnalyticsExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "session-analytics-exports")
	cfg.Telemetry.SessionAnalyticsExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	_, err := db.DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, identity_source, vlan, role, bandwidth_profile, radius_session_id,
		start_time, last_activity, end_time, stop_reason, bytes_in, bytes_out, acct_session_time
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-analytics-1", "alice", "aa:bb:cc:dd:ee:11", "192.168.50.111", "dot1x", "ldap", 20, "employee", "gold", "radius-11",
		"2026-05-25T08:00:00Z", "2026-05-25T08:20:00Z", "2026-05-25T08:30:00Z", "User-Request", 1024, 2048, 1800,
	)
	require.NoError(t, err)

	now := time.Date(2026, 5, 25, 11, 55, 0, 0, time.UTC)
	origNow := sessionAnalyticsExportNow
	sessionAnalyticsExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		sessionAnalyticsExportNow = origNow
	})

	runSessionAnalyticsExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(sessionAnalyticsExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])
	assert.EqualValues(t, defaultSessionAnalyticsWindowHours, runtimeStatus.Details["window_hours"])
	assert.EqualValues(t, defaultSessionAnalyticsBucketCount, runtimeStatus.Details["bucket_count"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/session-analytics-exports", nil)
	rec := httptest.NewRecorder()
	HandleListSessionAnalyticsExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus                `json:"runtime"`
		Exports []SessionAnalyticsExportArtifact `json:"exports"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Runtime)
	require.Len(t, payload.Exports, 2)
	assert.Equal(t, "ok", payload.Runtime.Status)

	formats := make([]string, 0, len(payload.Exports))
	for _, artifact := range payload.Exports {
		formats = append(formats, artifact.Format)
	}
	assert.ElementsMatch(t, []string{"json", "csv"}, formats)
}

func TestHandleDownloadSessionAnalyticsExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "session-analytics-export-downloads")
	cfg.Telemetry.SessionAnalyticsExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	_, err := db.DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, start_time, last_activity
	) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"session-analytics-2", "guest1", "aa:bb:cc:dd:ee:12", "192.168.50.112", "mab", "2026-05-25T09:00:00Z", "2026-05-25T09:05:00Z",
	)
	require.NoError(t, err)

	now := time.Date(2026, 5, 25, 12, 5, 0, 0, time.UTC)
	origNow := sessionAnalyticsExportNow
	sessionAnalyticsExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		sessionAnalyticsExportNow = origNow
	})

	runSessionAnalyticsExportCycle(context.Background(), cfg)

	artifacts, err := listSessionAnalyticsExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/session-analytics-exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadSessionAnalyticsExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Contains(t, rec.Body.String(), `"auth_method": ""`)
	assert.Contains(t, rec.Body.String(), `"mab"`)
}
