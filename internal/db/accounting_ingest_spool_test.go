package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountingIngestSpoolQueueClaimAndComplete(t *testing.T) {
	setupAccountingIngestSpoolDB(t)
	now := time.Now().UTC()
	event := AccountingEventRecord{
		AcctUniqueID:     "ingest-db-1",
		AcctSessionID:    "ingest-db-1",
		SessionKey:       "ingest-db-1",
		StatusType:       "Start",
		EventTime:        now.Format(time.RFC3339Nano),
		Username:         "alice",
		NASIPAddress:     "10.0.0.10",
		CallingStationID: "00-11-22-33-44-55",
		Source:           "unit-test",
	}

	record, inserted, err := EnqueueAccountingIngestSpool(AccountingIngestSpoolCreate{
		Event:         event,
		MaxAttempts:   3,
		NextAttemptAt: now.Add(-time.Second),
		ExpiresAt:     now.Add(time.Hour),
		OwnerNode:     "node-a",
	}, 10)
	require.NoError(t, err)
	assert.True(t, inserted)
	assert.Equal(t, AccountingIngestSpoolStatusQueued, record.Status)
	assert.NotEmpty(t, record.PayloadSHA256)

	summary, err := GetAccountingIngestSpoolSummary(10, 300)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.QueuedCount)
	assert.Equal(t, 1, summary.DueCount)

	claimed, err := ClaimAccountingIngestSpool(10, "node-b", now, time.Minute)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	assert.Equal(t, AccountingIngestSpoolStatusRetrying, claimed[0].Status)
	assert.Equal(t, "node-b", claimed[0].OwnerNode)

	require.NoError(t, CompleteAccountingIngestSpoolAttempt(claimed[0], AccountingIngestSpoolAttemptUpdate{
		Result:      AccountingIngestSpoolAttemptApplied,
		EventID:     event.EventID,
		LatencyMs:   7,
		AttemptedAt: now.Add(time.Second),
		Status:      AccountingIngestSpoolStatusApplied,
	}))

	summary, err = GetAccountingIngestSpoolSummary(10, 300)
	require.NoError(t, err)
	assert.Equal(t, 0, summary.QueuedCount)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 1, summary.AttemptCount)

	attempts, err := ListAccountingIngestSpoolAttempts(record.RecordID, 10)
	require.NoError(t, err)
	require.Len(t, attempts, 1)
	assert.Equal(t, AccountingIngestSpoolAttemptApplied, attempts[0].Result)
}

func TestAccountingIngestSpoolCapacityAndExpiration(t *testing.T) {
	setupAccountingIngestSpoolDB(t)
	now := time.Now().UTC()
	first := AccountingEventRecord{
		AcctUniqueID:  "ingest-capacity-1",
		AcctSessionID: "ingest-capacity-1",
		SessionKey:    "ingest-capacity-1",
		StatusType:    "Start",
		EventTime:     now.Format(time.RFC3339Nano),
		Source:        "unit-test",
	}
	second := first
	second.AcctUniqueID = "ingest-capacity-2"
	second.AcctSessionID = "ingest-capacity-2"
	second.SessionKey = "ingest-capacity-2"

	_, _, err := EnqueueAccountingIngestSpool(AccountingIngestSpoolCreate{
		Event:         first,
		MaxAttempts:   3,
		NextAttemptAt: now,
		ExpiresAt:     now.Add(time.Hour),
	}, 1)
	require.NoError(t, err)

	_, _, err = EnqueueAccountingIngestSpool(AccountingIngestSpoolCreate{
		Event:         second,
		MaxAttempts:   3,
		NextAttemptAt: now,
		ExpiresAt:     now.Add(time.Hour),
	}, 1)
	require.ErrorContains(t, err, "accounting ingest spool is full")

	expired, err := ExpireDueAccountingIngestSpool(now.Add(2 * time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 1, expired)

	summary, err := GetAccountingIngestSpoolSummary(1, 300)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.ExpiredCount)
	assert.Equal(t, 0, summary.QueuedCount)
}

func setupAccountingIngestSpoolDB(t *testing.T) {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "accounting-ingest-spool-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	t.Cleanup(func() {
		_ = Close()
		_ = os.Remove(dbPath)
	})
	require.NoError(t, Init(dbPath))
	require.NoError(t, Migrate())
}
