package radius

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestAccountingChargingReportReconcileAndExport(t *testing.T) {
	setupSQLAccountingDB(t)
	cfg := accountingChargingTestConfig()
	now := time.Now().UTC().Truncate(time.Second)
	_, err := db.IngestAccountingEvent(context.Background(), db.AccountingEventRecord{
		AcctUniqueID:     "radius-charge-1",
		AcctSessionID:    "radius-charge-1",
		SessionKey:       "radius-charge-1",
		StatusType:       "Stop",
		EventTime:        now.Format(time.RFC3339Nano),
		Username:         "billing@example.com",
		NASIPAddress:     "10.0.0.43",
		NASPortID:        "43",
		CallingStationID: "00-11-22-33-44-43",
		AcctInputOctets:  1 << 30,
		AcctOutputOctets: 1 << 30,
		AcctSessionTime:  3600,
		ServiceType:      "Framed-User",
		Class:            "service_key=internet;service_category=data;service_leg_id=radius-ppp",
		Source:           "unit-test",
	})
	require.NoError(t, err)
	_, err = db.ApplyPendingAccountingEvents(context.Background(), 10)
	require.NoError(t, err)

	reconcile, err := ReconcileAccountingCharging(context.Background(), cfg, 10)
	require.NoError(t, err)
	assert.Equal(t, "ok", reconcile.Status)
	assert.Equal(t, 1, reconcile.Result.Rated)
	assert.Equal(t, 1, reconcile.Summary.PendingExportRecords)

	report := BuildAccountingChargingReport(cfg)
	assert.True(t, report.Enabled)
	assert.Equal(t, "ready", report.Status)
	assert.Contains(t, report.Attributes, "Acct-Input-Gigawords")
	assert.Contains(t, report.RFCs, "RFC 2866")
	assert.Len(t, report.Recent, 1)
	assert.NotContains(t, report.Recent[0].UsernameHash, "billing")

	export, err := ExportAccountingCharging(context.Background(), cfg, "jsonl", 10, "ops")
	require.NoError(t, err)
	assert.Equal(t, "complete", export.Status)
	assert.Equal(t, 1, export.RecordCount)
	assert.NotEmpty(t, export.ManifestSHA256)

	report = BuildAccountingChargingReport(cfg)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 1, report.Summary.ExportedRecords)
	assert.Equal(t, 0, report.Summary.PendingExportRecords)
}

func TestAccountingChargingReportDegradesWhenExportDisabled(t *testing.T) {
	setupSQLAccountingDB(t)
	cfg := accountingChargingTestConfig()
	cfg.Radius.AccountingCharging.ExportEnabled = false
	report := BuildAccountingChargingReport(cfg)
	assert.Equal(t, "degraded", report.Status)
	assert.Contains(t, report.Message, "export is disabled")
}

func TestAccountingChargingExportRequiresRating(t *testing.T) {
	setupSQLAccountingDB(t)
	cfg := accountingChargingTestConfig()
	cfg.Radius.AccountingCharging.RatingEnabled = false

	result, err := ExportAccountingCharging(context.Background(), cfg, "jsonl", 10, "ops")
	require.NoError(t, err)
	assert.Equal(t, "disabled", result.Status)
	assert.Contains(t, result.Message, "requires rating")
}

func accountingChargingTestConfig() *config.Config {
	return &config.Config{Radius: config.RadiusConfig{AccountingCharging: config.RadiusAccountingChargingConfig{
		Enabled:                  true,
		RatingEnabled:            true,
		ExportEnabled:            true,
		ReconcileIntervalSeconds: 300,
		BatchSize:                100,
		MaxExportRecords:         100,
		ExportFormat:             "jsonl",
		DefaultPlan:              "standard",
		Currency:                 "USD",
		InputMicrosPerGiB:        1000000,
		OutputMicrosPerGiB:       1000000,
		SessionMicrosPerHour:     1000000,
		MinimumChargeMicros:      0,
		OpenRetentionDays:        30,
		ClosedRetentionDays:      365,
		ExportRetentionDays:      365,
		IntegritySampleLimit:     100,
	}}}
}
