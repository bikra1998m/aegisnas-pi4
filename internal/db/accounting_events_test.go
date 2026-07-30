package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountingEventLedgerDuplicateOrderingAndReplay(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	startTime := now.Add(-2 * time.Minute).Format(time.RFC3339Nano)
	stopTime := now.Format(time.RFC3339Nano)

	stopEvent := AccountingEventRecord{
		AcctUniqueID:       "acct-unique-1",
		AcctSessionID:      "acct-sess-1",
		SessionKey:         "acct-sess-1",
		StatusType:         "Stop",
		EventTime:          stopTime,
		Username:           "alice",
		NASIPAddress:       "10.0.0.2",
		NASPortID:          "7",
		CallingStationID:   "aa-bb-cc-dd-ee-ff",
		FramedIPAddress:    "192.0.2.10",
		AcctInputOctets:    3000,
		AcctOutputOctets:   4000,
		AcctSessionTime:    120,
		AcctTerminateCause: "User-Request",
		Source:             "packet-test",
	}
	ingestedStop, err := IngestAccountingEvent(ctx, stopEvent)
	require.NoError(t, err)
	appliedStop, err := ApplyAccountingEventByID(ctx, ingestedStop.Event.EventID)
	require.NoError(t, err)
	assert.Equal(t, 1, appliedStop.Applied)
	assert.Equal(t, 1, appliedStop.CreatedSessions)
	assert.Equal(t, 1, appliedStop.ClosedSessions)

	duplicateStop, err := IngestAccountingEvent(ctx, stopEvent)
	require.NoError(t, err)
	assert.True(t, duplicateStop.Duplicate)
	assert.Equal(t, int64(1), duplicateStop.DuplicateCount)
	appliedDuplicate, err := ApplyAccountingEventByID(ctx, duplicateStop.Event.EventID)
	require.NoError(t, err)
	assert.Equal(t, 0, appliedDuplicate.Applied)

	startEvent := AccountingEventRecord{
		AcctUniqueID:     "acct-unique-1",
		AcctSessionID:    "acct-sess-1",
		SessionKey:       "acct-sess-1",
		StatusType:       "Start",
		EventTime:        startTime,
		Username:         "alice",
		NASIPAddress:     "10.0.0.2",
		NASPortID:        "7",
		CallingStationID: "aa-bb-cc-dd-ee-ff",
		FramedIPAddress:  "192.0.2.10",
		AcctInputOctets:  0,
		AcctOutputOctets: 0,
		AcctSessionTime:  0,
		Source:           "packet-test",
	}
	ingestedStart, err := IngestAccountingEvent(ctx, startEvent)
	require.NoError(t, err)
	appliedStart, err := ApplyAccountingEventByID(ctx, ingestedStart.Event.EventID)
	require.NoError(t, err)
	assert.Equal(t, 1, appliedStart.Applied)
	assert.Equal(t, 1, appliedStart.Reordered)

	var sessionStart, sessionEnd, stopReason string
	var bytesIn, bytesOut int
	require.NoError(t, DB.QueryRow(`SELECT COALESCE(CAST(start_time AS TEXT), ''), COALESCE(CAST(end_time AS TEXT), ''), COALESCE(stop_reason, ''), bytes_in, bytes_out
		FROM sessions WHERE id = ?`, "acct-sess-1").Scan(&sessionStart, &sessionEnd, &stopReason, &bytesIn, &bytesOut))
	assert.Equal(t, startTime, normalizeAccountingTimeString(sessionStart))
	assert.Equal(t, stopTime, normalizeAccountingTimeString(sessionEnd))
	assert.Equal(t, "User-Request", stopReason)
	assert.Equal(t, 3000, bytesIn)
	assert.Equal(t, 4000, bytesOut)

	summary, err := GetAccountingEventSummary(time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 2, summary.AppliedEvents)
	assert.Equal(t, 1, summary.DuplicateEvents)
	assert.Equal(t, 1, summary.ReorderedEvents)

	replayed, err := ReplayAccountingEvents(ctx, 10, "acct-sess-1")
	require.NoError(t, err)
	assert.Equal(t, 2, replayed.Scanned)
	assert.Equal(t, 2, replayed.Applied)
}
