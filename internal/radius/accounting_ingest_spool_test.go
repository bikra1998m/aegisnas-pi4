package radius

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestAccountingIngestSpoolAppliesThroughLedger(t *testing.T) {
	setupAccountingIngestSpoolTestDB(t)
	cfg := accountingIngestSpoolTestConfig()
	now := time.Now().UTC()
	rec := &AccountingRecord{
		SessionID:        "ingest-radius-1",
		Username:         "nina",
		NASIPAddress:     "10.0.0.31",
		NASPort:          31,
		AcctStatusType:   "Start",
		CallingStationID: "00-11-22-33-44-31",
		FramedIPAddress:  "192.0.2.31",
		Timestamp:        now,
	}

	require.NoError(t, processAccountingWithIngestSpool(context.Background(), cfg, accountingEventFromAccounting(rec)))

	uniqueID := db.FreeRADIUSAcctUniqueID("ingest-radius-1", "nina", "10.0.0.31", "31", "00-11-22-33-44-31")
	radacct, err := db.GetFreeRADIUSAccountingByUniqueID(uniqueID)
	require.NoError(t, err)
	assert.Equal(t, "reconciled", radacct.AegisReconcileStatus)
	assert.Equal(t, "192.0.2.31", radacct.FramedIPAddress)

	summary, err := db.GetAccountingIngestSpoolSummary(10, 300)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 0, summary.QueuedCount)
	assert.Equal(t, 1, summary.AttemptCount)

	report := BuildAccountingIngestSpoolReport(cfg)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 1, report.Summary.AppliedCount)
}

func TestAccountingIngestSpoolReplayPoisonsChecksumMismatch(t *testing.T) {
	setupAccountingIngestSpoolTestDB(t)
	cfg := accountingIngestSpoolTestConfig()
	cfg.Radius.AccountingIngestSpool.MaxAttempts = 1
	now := time.Now().UTC()
	event := db.AccountingEventRecord{
		AcctUniqueID:  "ingest-poison-1",
		AcctSessionID: "ingest-poison-1",
		SessionKey:    "ingest-poison-1",
		StatusType:    "Start",
		EventTime:     now.Format(time.RFC3339Nano),
		Username:      "omar",
		NASIPAddress:  "10.0.0.32",
		Source:        "unit-test",
	}
	queued, _, err := db.EnqueueAccountingIngestSpool(db.AccountingIngestSpoolCreate{
		Event:         event,
		MaxAttempts:   1,
		NextAttemptAt: now.Add(-time.Second),
		ExpiresAt:     now.Add(time.Hour),
		OwnerNode:     "node-a",
	}, 10)
	require.NoError(t, err)
	_, err = db.DB.Exec(`UPDATE radius_accounting_ingest_spool SET payload_sha256 = ? WHERE record_id = ?`, "bad-sha", queued.RecordID)
	require.NoError(t, err)

	replay, err := ReplayAccountingIngestSpool(context.Background(), cfg, 10)
	require.NoError(t, err)
	assert.Equal(t, "degraded", replay.Status)
	assert.Equal(t, 1, replay.Poisoned)

	summary, err := db.GetAccountingIngestSpoolSummary(10, 300)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.PoisonCount)
	assert.Equal(t, "payload checksum mismatch", summary.LastError)
}

func TestBuildAccountingIngestSpoolReportDetectsSLOBreach(t *testing.T) {
	setupAccountingIngestSpoolTestDB(t)
	cfg := accountingIngestSpoolTestConfig()
	cfg.Radius.AccountingIngestSpool.LossSLOSeconds = 1
	old := time.Now().UTC().Add(-5 * time.Minute)
	event := db.AccountingEventRecord{
		AcctUniqueID:  "ingest-slo-1",
		AcctSessionID: "ingest-slo-1",
		SessionKey:    "ingest-slo-1",
		StatusType:    "Interim-Update",
		EventTime:     old.Format(time.RFC3339Nano),
		Source:        "unit-test",
	}
	queued, _, err := db.EnqueueAccountingIngestSpool(db.AccountingIngestSpoolCreate{
		Event:         event,
		MaxAttempts:   3,
		NextAttemptAt: old,
		ExpiresAt:     time.Now().UTC().Add(time.Hour),
		OwnerNode:     "node-a",
	}, 10)
	require.NoError(t, err)
	_, err = db.DB.Exec(`UPDATE radius_accounting_ingest_spool SET created_at = ?, updated_at = ?, next_attempt_at = ? WHERE record_id = ?`,
		old.Format(time.RFC3339Nano), old.Format(time.RFC3339Nano), old.Format(time.RFC3339Nano), queued.RecordID)
	require.NoError(t, err)

	report := BuildAccountingIngestSpoolReport(cfg)
	assert.Equal(t, "degraded", report.Status)
	assert.Equal(t, 1, report.Summary.LossSLOBreachCount)
	assert.Contains(t, report.Message, "loss SLO")
}

func setupAccountingIngestSpoolTestDB(t *testing.T) {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "radius-accounting-ingest-spool-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
	})
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
}

func accountingIngestSpoolTestConfig() *config.Config {
	cfg := accountingSpoolTestConfig()
	cfg.Radius.AccountingIngestSpool = config.RadiusAccountingIngestSpoolConfig{
		Enabled:                 true,
		ReplayEnabled:           true,
		MaxQueueRecords:         10,
		MaxAttempts:             3,
		InitialRetrySeconds:     1,
		MaxRetrySeconds:         4,
		RecordTTLSeconds:        3600,
		ReplayIntervalSeconds:   1,
		BatchSize:               10,
		LockSeconds:             30,
		AppliedRetentionSeconds: 3600,
		PoisonRetentionSeconds:  3600,
		LossSLOSeconds:          300,
	}
	return cfg
}
