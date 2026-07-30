package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFreeRADIUSAccountingReconcileLifecycle(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)

	now := time.Now().UTC()
	uniqueID := FreeRADIUSAcctUniqueID("sess-1", "alice", "10.0.0.2", "7", "aa-bb-cc-dd-ee-ff")
	inserted, err := UpsertFreeRADIUSAccountingRecord(context.Background(), FreeRADIUSAccountingRecord{
		AcctSessionID:    "sess-1",
		AcctUniqueID:     uniqueID,
		Username:         "alice",
		NASIPAddress:     "10.0.0.2",
		NASPortID:        "7",
		AcctStartTime:    now.Add(-10 * time.Minute).Format(time.RFC3339Nano),
		AcctUpdateTime:   now.Format(time.RFC3339Nano),
		AcctInputOctets:  1234,
		AcctOutputOctets: 5678,
		CalledStationID:  "ap-1",
		CallingStationID: "aa-bb-cc-dd-ee-ff",
		FramedIPAddress:  "192.0.2.10",
		Class:            "class-a",
	})
	require.NoError(t, err)
	assert.Equal(t, "pending", inserted.AegisReconcileStatus)

	summary, err := GetFreeRADIUSAccountingSummary(time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.RadAcctRows)
	assert.Equal(t, 1, summary.PendingRows)

	result, err := ReconcileFreeRADIUSAccounting(10)
	require.NoError(t, err)
	assert.Equal(t, "ok", result.Status)
	assert.Equal(t, 1, result.Scanned)
	assert.Equal(t, 1, result.Reconciled)
	assert.Equal(t, 1, result.CreatedSessions)

	var username string
	var bytesIn int
	require.NoError(t, DB.QueryRow(`SELECT username, bytes_in FROM sessions WHERE id = ?`, "sess-1").Scan(&username, &bytesIn))
	assert.Equal(t, "alice", username)
	assert.Equal(t, 1234, bytesIn)

	_, err = UpsertFreeRADIUSAccountingRecord(context.Background(), FreeRADIUSAccountingRecord{
		AcctSessionID:      "sess-1",
		AcctUniqueID:       uniqueID,
		Username:           "alice",
		NASIPAddress:       "10.0.0.2",
		NASPortID:          "7",
		AcctUpdateTime:     now.Add(5 * time.Minute).Format(time.RFC3339Nano),
		AcctStopTime:       now.Add(5 * time.Minute).Format(time.RFC3339Nano),
		AcctSessionTime:    900,
		AcctInputOctets:    2345,
		AcctOutputOctets:   6789,
		AcctTerminateCause: "User-Request",
		CallingStationID:   "aa-bb-cc-dd-ee-ff",
		FramedIPAddress:    "192.0.2.10",
	})
	require.NoError(t, err)
	result, err = ReconcileFreeRADIUSAccounting(10)
	require.NoError(t, err)
	assert.Equal(t, 1, result.ClosedSessions)

	var stopReason string
	var sessionTime int
	require.NoError(t, DB.QueryRow(`SELECT stop_reason, acct_session_time FROM sessions WHERE id = ?`, "sess-1").Scan(&stopReason, &sessionTime))
	assert.Equal(t, "User-Request", stopReason)
	assert.Equal(t, 900, sessionTime)

	require.NoError(t, RecordFreeRADIUSPostAuth(FreeRADIUSPostAuthRecord{
		Username:         "alice",
		Pass:             "[redacted]",
		Reply:            "Access-Accept",
		CalledStationID:  "ap-1",
		CallingStationID: "aa-bb-cc-dd-ee-ff",
		NASIPAddress:     "10.0.0.2",
		NASIdentifier:    "aegisnas",
	}))
	summary, err = GetFreeRADIUSAccountingSummary(time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.PostAuthRows)

	old := now.Add(-400 * 24 * time.Hour).Format(time.RFC3339Nano)
	_, err = DB.Exec(`UPDATE radacct SET acctstoptime = ?, acctupdatetime = ?, aegis_reconcile_status = 'reconciled'`, old, old)
	require.NoError(t, err)
	_, err = DB.Exec(`UPDATE radpostauth SET authdate = ?`, old)
	require.NoError(t, err)
	require.NoError(t, PruneFreeRADIUSSQLAccounting(365*24*time.Hour, 30*24*time.Hour, now))

	summary, err = GetFreeRADIUSAccountingSummary(time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 0, summary.RadAcctRows)
	assert.Equal(t, 0, summary.PostAuthRows)
}

func setupFreeRADIUSAccountingTestDB(t *testing.T) {
	t.Helper()
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
	})
}
