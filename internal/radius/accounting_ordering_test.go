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

func TestBuildAccountingOrderingReportAndReplay(t *testing.T) {
	setupSQLAccountingDB(t)
	cfg := accountingOrderingTestConfig()
	now := time.Now().UTC()

	ingested, err := db.IngestAccountingEvent(context.Background(), db.AccountingEventRecord{
		AcctUniqueID:     "acct-ordering-1",
		AcctSessionID:    "acct-ordering-1",
		SessionKey:       "acct-ordering-1",
		StatusType:       "Start",
		EventTime:        now.Format(time.RFC3339Nano),
		Username:         "casey",
		NASIPAddress:     "10.0.0.5",
		NASPortID:        "11",
		CallingStationID: "00-11-22-33-44-55",
		FramedIPAddress:  "192.0.2.44",
		Source:           "unit-test",
	})
	require.NoError(t, err)

	report := BuildAccountingOrderingReport(cfg)
	assert.True(t, report.Enabled)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 1, report.Summary.PendingEvents)

	applied, err := db.ApplyAccountingEventByID(context.Background(), ingested.Event.EventID)
	require.NoError(t, err)
	assert.Equal(t, 1, applied.Applied)

	report = BuildAccountingOrderingReport(cfg)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 1, report.Summary.AppliedEvents)

	replayed, err := ReplayAccountingOrdering(context.Background(), cfg, 10, "acct-ordering-1")
	require.NoError(t, err)
	assert.Equal(t, "ok", replayed.Status)
	assert.Equal(t, 1, replayed.Result.Applied)
}

func accountingOrderingTestConfig() *config.Config {
	cfg := sqlAccountingTestConfig()
	cfg.Radius.AccountingOrdering = config.RadiusAccountingOrderingConfig{
		Enabled:                true,
		ReplayEnabled:          true,
		SequenceWindowSeconds:  60,
		LateStopWindowSeconds:  3600,
		MaxReplayBatch:         10,
		DuplicateRetentionDays: 30,
	}
	return cfg
}
