package radius

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestSendAccountingQueuesAndReplaySendsDurableRecord(t *testing.T) {
	setupAccountingSpoolDB(t)
	cfg := accountingSpoolTestConfig()
	originalSender := accountingPacketSender
	defer func() { accountingPacketSender = originalSender }()

	accountingPacketSender = func(context.Context, *config.Config, *AccountingRecord) (accountingSendResult, error) {
		return accountingSendResult{}, errors.New("proxy accounting timeout")
	}
	rec := &AccountingRecord{
		SessionID:        "sess-1",
		Username:         "alice",
		AcctStatusType:   "Start",
		CallingStationID: "aa:bb:cc:dd:ee:ff",
		Timestamp:        time.Now().UTC(),
	}
	err := SendAccounting(context.Background(), cfg, rec)
	require.ErrorContains(t, err, "proxy accounting timeout")

	summary, err := db.GetRadiusAccountingSpoolSummary(10)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.QueuedCount)

	accountingPacketSender = func(context.Context, *config.Config, *AccountingRecord) (accountingSendResult, error) {
		return accountingSendResult{ResponseCode: "Accounting-Response", Latency: 5 * time.Millisecond}, nil
	}
	report, err := ReplayAccountingSpool(context.Background(), cfg, 10)
	require.NoError(t, err)
	assert.Equal(t, "ok", report.Status)
	assert.Equal(t, 1, report.Sent)
	assert.Equal(t, 0, report.Failed)

	summary, err = db.GetRadiusAccountingSpoolSummary(10)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.SentCount)
	assert.Equal(t, 0, summary.QueuedCount)
}

func TestReplayAccountingSpoolPoisonsAfterMaxAttempts(t *testing.T) {
	setupAccountingSpoolDB(t)
	cfg := accountingSpoolTestConfig()
	cfg.Radius.Upstream.AccountingSpool.MaxAttempts = 1
	originalSender := accountingPacketSender
	defer func() { accountingPacketSender = originalSender }()
	accountingPacketSender = func(context.Context, *config.Config, *AccountingRecord) (accountingSendResult, error) {
		return accountingSendResult{}, errors.New("still down")
	}

	queued, _, err := queueAccountingFailure(context.Background(), cfg, &AccountingRecord{
		SessionID:      "sess-poison",
		Username:       "bob",
		AcctStatusType: "Stop",
		Timestamp:      time.Now().UTC(),
	}, "initial failure")
	require.NoError(t, err)
	_, err = db.DB.Exec(`UPDATE radius_accounting_spool SET next_attempt_at = ? WHERE record_id = ?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), queued.RecordID)
	require.NoError(t, err)

	report, err := ReplayAccountingSpool(context.Background(), cfg, 10)
	require.NoError(t, err)
	assert.Equal(t, "degraded", report.Status)
	assert.Equal(t, 1, report.Poisoned)

	summary, err := db.GetRadiusAccountingSpoolSummary(10)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.PoisonCount)
}

func TestBuildAccountingSpoolReportDisabledWhenUpstreamOff(t *testing.T) {
	cfg := accountingSpoolTestConfig()
	cfg.Radius.Upstream.Enabled = false

	report := BuildAccountingSpoolReport(cfg)

	assert.False(t, report.Enabled)
	assert.Equal(t, "disabled", report.Status)
}

func setupAccountingSpoolDB(t *testing.T) {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "radius-accounting-spool-*.db")
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

func accountingSpoolTestConfig() *config.Config {
	cfg := proxyRoutingTestConfig()
	cfg.Radius.Secret = "secret"
	cfg.Radius.NASIdentifier = "node-a"
	cfg.Radius.Upstream.AccountingSpool = config.RadiusAccountingSpoolConfig{
		Enabled:                true,
		MaxQueueRecords:        10,
		MaxAttempts:            3,
		InitialRetrySeconds:    1,
		MaxRetrySeconds:        4,
		RecordTTLSeconds:       3600,
		ReplayIntervalSeconds:  1,
		BatchSize:              10,
		LockSeconds:            30,
		SentRetentionSeconds:   3600,
		PoisonRetentionSeconds: 3600,
	}
	return cfg
}
