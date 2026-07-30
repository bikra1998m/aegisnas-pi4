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

func TestBuildSQLAccountingReportAndReconcile(t *testing.T) {
	setupSQLAccountingDB(t)
	cfg := sqlAccountingTestConfig()
	now := time.Now().UTC()

	_, err := db.UpsertFreeRADIUSAccountingRecord(context.Background(), db.FreeRADIUSAccountingRecord{
		AcctSessionID:    "sql-sess-1",
		AcctUniqueID:     db.FreeRADIUSAcctUniqueID("sql-sess-1", "carol", "10.0.0.9", "1", "00-11-22-33-44-55"),
		Username:         "carol",
		NASIPAddress:     "10.0.0.9",
		NASPortID:        "1",
		AcctStartTime:    now.Add(-time.Minute).Format(time.RFC3339Nano),
		AcctUpdateTime:   now.Format(time.RFC3339Nano),
		AcctInputOctets:  100,
		AcctOutputOctets: 200,
		CallingStationID: "00-11-22-33-44-55",
		FramedIPAddress:  "192.0.2.50",
	})
	require.NoError(t, err)

	report := BuildSQLAccountingReport(cfg)
	assert.True(t, report.Enabled)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 1, report.Summary.PendingRows)

	reconciled, err := ReconcileSQLAccounting(context.Background(), cfg, 10)
	require.NoError(t, err)
	assert.Equal(t, "ok", reconciled.Status)
	assert.Equal(t, 1, reconciled.Result.Reconciled)
	assert.Equal(t, 1, reconciled.Summary.ReconciledRows)
}

func TestProcessAccountingMirrorsRadAcct(t *testing.T) {
	setupSQLAccountingDB(t)
	now := time.Now().UTC()
	rec := &AccountingRecord{
		SessionID:        "local-sess-1",
		Username:         "dana",
		NASIPAddress:     "10.0.0.3",
		NASPort:          12,
		AcctStatusType:   "Start",
		CalledStationID:  "ap-main",
		CallingStationID: "aa:bb:cc:dd:ee:ff",
		FramedIPAddress:  "192.0.2.80",
		RadiusClass:      "radius-class",
		Timestamp:        now,
	}
	require.NoError(t, ProcessAccounting(rec))

	rec.AcctStatusType = "Interim-Update"
	rec.AcctInputOctets = 2048
	rec.AcctOutputOctets = 4096
	rec.AcctSessionTime = 60
	rec.Timestamp = now.Add(time.Minute)
	require.NoError(t, ProcessAccounting(rec))

	rec.AcctStatusType = "Stop"
	rec.StopReason = "User-Request"
	rec.AcctSessionTime = 120
	rec.Timestamp = now.Add(2 * time.Minute)
	require.NoError(t, ProcessAccounting(rec))

	uniqueID := db.FreeRADIUSAcctUniqueID("local-sess-1", "dana", "10.0.0.3", "12", "aa:bb:cc:dd:ee:ff")
	radacct, err := db.GetFreeRADIUSAccountingByUniqueID(uniqueID)
	require.NoError(t, err)
	assert.Equal(t, "reconciled", radacct.AegisReconcileStatus)
	assert.NotEmpty(t, radacct.AcctStopTime)
	assert.Equal(t, uint64(2048), radacct.AcctInputOctets)
	assert.Equal(t, "radius-class", radacct.Class)

	var stopReason string
	require.NoError(t, db.DB.QueryRow(`SELECT stop_reason FROM sessions WHERE id = ?`, "local-sess-1").Scan(&stopReason))
	assert.Equal(t, "User-Request", stopReason)
}

func setupSQLAccountingDB(t *testing.T) {
	t.Helper()
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
	})
}

func sqlAccountingTestConfig() *config.Config {
	cfg := accountingSpoolTestConfig()
	cfg.Radius.SQLAccounting = config.RadiusSQLAccountingConfig{
		Enabled:                  true,
		ReconcileEnabled:         true,
		ReconcileIntervalSeconds: 1,
		BatchSize:                10,
		StaleAfterSeconds:        60,
		AccountingRetentionDays:  365,
		PostAuthRetentionDays:    30,
	}
	return cfg
}
