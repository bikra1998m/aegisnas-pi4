package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

func TestSIEMExporterWebhookAdvancesCursorAndStopsWhenIdle(t *testing.T) {
	initTelemetryTestDB(t)

	require.NoError(t, insertAuditEvent("operator", "login", "guest portal login", "success"))
	require.NoError(t, insertAlertEvent("warning", "system", "High CPU usage", "CPU at 94%"))

	var (
		requestCount int
		requestBody  map[string]any
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "Bearer secret-token", r.Header.Get("Authorization"))
		assert.Equal(t, "secret-token", r.Header.Get("X-API-Key"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &requestBody))
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer server.Close()

	t.Setenv("AEGIS_SIEM_TEST_KEY", "secret-token")
	cfg := telemetryTestConfig()
	cfg.Integrations.SIEM.Provider = "webhook"
	cfg.Integrations.SIEM.Endpoint = server.URL

	exporter := NewSIEMExporter(cfg, zap.NewNop(), server.Client())
	exporter.now = func() time.Time {
		return time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC)
	}

	exporter.runOnce(context.Background())

	require.Equal(t, 1, requestCount)
	require.Equal(t, "AegisNAS", requestBody["product"])
	counts, ok := requestBody["counts"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(1), counts["audit_logs"])
	assert.Equal(t, float64(1), counts["alerts"])

	status, err := db.GetRuntimeStatus(siemExportComponent)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Equal(t, "ok", status.Status)
	assert.Equal(t, int64(1), detailInt64(status.Details, "last_audit_id"))
	assert.Equal(t, int64(1), detailInt64(status.Details, "last_alert_id"))
	assert.Equal(t, "2026-05-01T12:00:00Z", status.Details["last_exported_at"])

	exporter.runOnce(context.Background())

	assert.Equal(t, 1, requestCount)
	status, err = db.GetRuntimeStatus(siemExportComponent)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Equal(t, "ok", status.Status)
	assert.Equal(t, "SIEM export is idle; no new events are pending.", status.Message)
}

func TestSIEMExporterMarksMissingAPIKeyDegraded(t *testing.T) {
	initTelemetryTestDB(t)

	cfg := telemetryTestConfig()
	cfg.Integrations.SIEM.Provider = "webhook"
	cfg.Integrations.SIEM.Endpoint = "https://example.invalid/siem"
	cfg.Integrations.SIEM.APIKeyEnv = "AEGIS_SIEM_MISSING"

	exporter := NewSIEMExporter(cfg, zap.NewNop(), nil)
	exporter.runOnce(context.Background())

	status, err := db.GetRuntimeStatus(siemExportComponent)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Equal(t, "degraded", status.Status)
	assert.Contains(t, status.Message, "AEGIS_SIEM_MISSING")
}

func TestSIEMExporterBuildsProviderRequests(t *testing.T) {
	cfg := telemetryTestConfig()
	cfg.Integrations.SIEM.Endpoint = "https://siem.example.test/ingest"
	exporter := NewSIEMExporter(cfg, zap.NewNop(), nil)
	exporter.now = func() time.Time {
		return time.Date(2026, time.May, 1, 13, 15, 0, 0, time.UTC)
	}
	audits := []siemAuditEvent{{ID: 2, Timestamp: "2026-05-01T13:10:00Z", User: "guest1", Action: "login", Result: "success"}}
	alerts := []siemAlertEvent{{ID: 9, Severity: "warning", Source: "system", Message: "Memory pressure", CreatedAt: "2026-05-01T13:11:00Z"}}

	cfg.Integrations.SIEM.Provider = "splunk-hec"
	splunkReq, _, err := exporter.buildRequest(context.Background(), "splunk-token", audits, alerts)
	require.NoError(t, err)
	assert.Equal(t, "Splunk splunk-token", splunkReq.Header.Get("Authorization"))
	splunkBody, err := io.ReadAll(splunkReq.Body)
	require.NoError(t, err)
	assert.Contains(t, string(splunkBody), `"sourcetype":"aegisnas:audit"`)
	assert.Contains(t, string(splunkBody), `"sourcetype":"aegisnas:alert"`)

	cfg.Integrations.SIEM.Provider = "elastic"
	elasticReq, _, err := exporter.buildRequest(context.Background(), "elastic-token", audits, alerts)
	require.NoError(t, err)
	assert.Equal(t, "ApiKey elastic-token", elasticReq.Header.Get("Authorization"))
	assert.Equal(t, "application/x-ndjson", elasticReq.Header.Get("Content-Type"))
	elasticBody, err := io.ReadAll(elasticReq.Body)
	require.NoError(t, err)
	assert.Contains(t, string(elasticBody), `"index":{"_index":"aegisnas-audit"}`)
	assert.Contains(t, string(elasticBody), `"index":{"_index":"aegisnas-alert"}`)
}

func initTelemetryTestDB(t *testing.T) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "telemetry-test.db")
	require.NoError(t, db.Init(path))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = nil
	})
}

func telemetryTestConfig() *config.Config {
	return &config.Config{
		Integrations: config.IntegrationsConfig{
			SIEM: config.SIEMConfig{
				Enabled:   true,
				Provider:  "webhook",
				Endpoint:  "https://siem.example.test/events",
				APIKeyEnv: "AEGIS_SIEM_TEST_KEY",
				BatchSize: 25,
			},
		},
	}
}

func insertAuditEvent(user, action, details, result string) error {
	_, err := db.DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address)
		VALUES (?, ?, ?, ?, ?, ?)`, time.Now().UTC(), user, action, details, result, "192.168.50.10")
	return err
}

func insertAlertEvent(severity, source, message, details string) error {
	_, err := db.DB.Exec(`INSERT INTO alerts (severity, source, message, details, acknowledged, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, severity, source, message, details, false, time.Now().UTC())
	return err
}
