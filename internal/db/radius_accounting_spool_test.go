package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRadiusAccountingSpoolLifecycle(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "accounting-spool-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	defer os.Remove(dbPath)

	require.NoError(t, Init(dbPath))
	defer Close()
	require.NoError(t, Migrate())

	now := time.Now().UTC()
	create := RadiusAccountingSpoolCreate{
		RecordID:       "acct-test",
		Route:          "corp",
		Realm:          "corp.example.com",
		ServerName:     "primary",
		Username:       "alice",
		SessionID:      "s1",
		AcctStatusType: "Start",
		PayloadJSON:    `{"SessionID":"s1","Username":"alice","AcctStatusType":"Start"}`,
		PayloadSHA256:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		MaxAttempts:    3,
		NextAttemptAt:  now.Add(-time.Second),
		ExpiresAt:      now.Add(time.Hour),
		OwnerNode:      "node-a",
	}
	record, queued, err := EnqueueRadiusAccountingSpool(create, 10)
	require.NoError(t, err)
	assert.True(t, queued)
	assert.Equal(t, RadiusAccountingSpoolStatusQueued, record.Status)

	duplicate, queued, err := EnqueueRadiusAccountingSpool(create, 10)
	require.NoError(t, err)
	assert.False(t, queued)
	assert.Equal(t, record.ID, duplicate.ID)

	claimed, err := ClaimRadiusAccountingSpool(10, "node-b", now, time.Minute)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	assert.Equal(t, RadiusAccountingSpoolStatusRetrying, claimed[0].Status)
	assert.Equal(t, "node-b", claimed[0].OwnerNode)

	nextAttempt := now.Add(30 * time.Second)
	err = CompleteRadiusAccountingSpoolAttempt(claimed[0], RadiusAccountingSpoolAttemptUpdate{
		Result:        RadiusAccountingSpoolAttemptFailed,
		Error:         "timeout",
		ResponseCode:  "",
		Route:         claimed[0].Route,
		Realm:         claimed[0].Realm,
		ServerName:    claimed[0].ServerName,
		AttemptedAt:   now,
		NextAttemptAt: nextAttempt,
		Status:        RadiusAccountingSpoolStatusQueued,
	})
	require.NoError(t, err)

	summary, err := GetRadiusAccountingSpoolSummary(10)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.QueuedCount)
	assert.Equal(t, 1, summary.AttemptCount)

	attempts, err := ListRadiusAccountingSpoolAttempts("acct-test", 10)
	require.NoError(t, err)
	require.Len(t, attempts, 1)
	assert.Equal(t, RadiusAccountingSpoolAttemptFailed, attempts[0].Result)
	assert.Equal(t, "timeout", attempts[0].Error)

	record, err = GetRadiusAccountingSpoolByRecordID("acct-test")
	require.NoError(t, err)
	err = CompleteRadiusAccountingSpoolAttempt(record, RadiusAccountingSpoolAttemptUpdate{
		Result:       RadiusAccountingSpoolAttemptSent,
		ResponseCode: "Accounting-Response",
		AttemptedAt:  now.Add(time.Minute),
		Status:       RadiusAccountingSpoolStatusSent,
	})
	require.NoError(t, err)

	summary, err = GetRadiusAccountingSpoolSummary(10)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.SentCount)
	assert.Equal(t, 2, summary.AttemptCount)
}

func TestRadiusAccountingSpoolCapacityAndExpiry(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "accounting-spool-capacity-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	defer os.Remove(dbPath)

	require.NoError(t, Init(dbPath))
	defer Close()
	require.NoError(t, Migrate())

	now := time.Now().UTC()
	create := RadiusAccountingSpoolCreate{
		RecordID:       "acct-full",
		PayloadJSON:    `{}`,
		PayloadSHA256:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		MaxAttempts:    1,
		NextAttemptAt:  now,
		ExpiresAt:      now.Add(-time.Second),
		AcctStatusType: "Stop",
	}
	_, queued, err := EnqueueRadiusAccountingSpool(create, 1)
	require.NoError(t, err)
	assert.True(t, queued)
	_, _, err = EnqueueRadiusAccountingSpool(RadiusAccountingSpoolCreate{
		RecordID:      "acct-overflow",
		PayloadJSON:   `{}`,
		PayloadSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		MaxAttempts:   1,
		NextAttemptAt: now,
		ExpiresAt:     now.Add(time.Hour),
	}, 1)
	assert.ErrorContains(t, err, "spool is full")

	expired, err := ExpireDueRadiusAccountingSpool(now)
	require.NoError(t, err)
	assert.Equal(t, 1, expired)
	summary, err := GetRadiusAccountingSpoolSummary(1)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.ExpiredCount)
}
