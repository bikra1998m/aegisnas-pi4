package db

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountingCountersGigawordsAndResetDetection(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	totalInput := uint64(1<<32) + 123
	totalOutput := uint64(2<<32) + 456

	ingested, err := IngestAccountingEvent(ctx, AccountingEventRecord{
		AcctUniqueID:     "counter-unique-1",
		AcctSessionID:    "counter-sess-1",
		SessionKey:       "counter-sess-1",
		StatusType:       "Interim-Update",
		EventTime:        now.Format(time.RFC3339Nano),
		Username:         "nora",
		NASIPAddress:     "10.0.0.21",
		NASPortID:        "19",
		CallingStationID: "00-11-22-33-44-77",
		AcctInputOctets:  totalInput,
		AcctOutputOctets: totalOutput,
		AcctSessionTime:  120,
		Source:           "packet-test",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(123), ingested.Event.AcctInputOctets)
	assert.Equal(t, uint64(1), ingested.Event.AcctInputGigawords)
	assert.Equal(t, strconv.FormatUint(totalInput, 10), ingested.Event.AcctInputOctets64)
	assert.Equal(t, "gigaword", ingested.Event.CounterStatus)

	applied, err := ApplyAccountingEventByID(ctx, ingested.Event.EventID)
	require.NoError(t, err)
	assert.Equal(t, 1, applied.Applied)

	var bytesIn, bytesOut int64
	require.NoError(t, DB.QueryRow(`SELECT bytes_in, bytes_out FROM sessions WHERE id = ?`, "counter-sess-1").Scan(&bytesIn, &bytesOut))
	assert.Equal(t, int64(totalInput), bytesIn)
	assert.Equal(t, int64(totalOutput), bytesOut)

	var inputLow, inputHigh int64
	var input64, counterStatus string
	require.NoError(t, DB.QueryRow(`SELECT acctinputoctets, acctinputgigawords, aegis_input_octets_64, aegis_counter_status
		FROM radacct WHERE acctuniqueid = ?`, "counter-unique-1").Scan(&inputLow, &inputHigh, &input64, &counterStatus))
	assert.Equal(t, int64(123), inputLow)
	assert.Equal(t, int64(1), inputHigh)
	assert.Equal(t, strconv.FormatUint(totalInput, 10), input64)
	assert.Equal(t, "gigaword", counterStatus)

	reset, err := IngestAccountingEvent(ctx, AccountingEventRecord{
		AcctUniqueID:     "counter-unique-2",
		AcctSessionID:    "counter-sess-1",
		SessionKey:       "counter-sess-1",
		StatusType:       "Interim-Update",
		EventTime:        now.Add(time.Minute).Format(time.RFC3339Nano),
		Username:         "nora",
		NASIPAddress:     "10.0.0.21",
		NASPortID:        "19",
		CallingStationID: "00-11-22-33-44-77",
		AcctInputOctets:  17,
		AcctOutputOctets: 31,
		AcctSessionTime:  180,
		Source:           "packet-test",
	})
	require.NoError(t, err)
	_, err = ApplyAccountingEventByID(ctx, reset.Event.EventID)
	require.NoError(t, err)

	storedReset, err := GetAccountingEventByEventID(reset.Event.EventID)
	require.NoError(t, err)
	assert.True(t, storedReset.CounterResetDetected)
	assert.Equal(t, "reset_detected", storedReset.CounterStatus)

	require.NoError(t, DB.QueryRow(`SELECT bytes_in, bytes_out FROM sessions WHERE id = ?`, "counter-sess-1").Scan(&bytesIn, &bytesOut))
	assert.Equal(t, int64(totalInput), bytesIn)
	assert.Equal(t, int64(totalOutput), bytesOut)

	summary, err := GetAccountingCounterSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.ResetEvents)
	assert.GreaterOrEqual(t, summary.RolloverEvents, 1)
	assert.Equal(t, strconv.FormatUint(totalInput, 10), summary.MaxInputOctets64)
}

func TestFreeRADIUSAccountingGigawordReconcile(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	totalInput := uint64(3<<32) + 222
	totalOutput := uint64(4<<32) + 333
	_, err := UpsertFreeRADIUSAccountingRecord(context.Background(), FreeRADIUSAccountingRecord{
		AcctSessionID:       "radacct-giga-1",
		AcctUniqueID:        "radacct-giga-1",
		Username:            "omar",
		NASIPAddress:        "10.0.0.22",
		NASPortID:           "20",
		AcctStartTime:       time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
		AcctUpdateTime:      time.Now().UTC().Format(time.RFC3339Nano),
		AcctInputOctets:     222,
		AcctInputGigawords:  3,
		AcctOutputOctets:    333,
		AcctOutputGigawords: 4,
	})
	require.NoError(t, err)

	result, err := ReconcileFreeRADIUSAccounting(10)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Reconciled)

	var bytesIn, bytesOut int64
	require.NoError(t, DB.QueryRow(`SELECT bytes_in, bytes_out FROM sessions WHERE id = ?`, "radacct-giga-1").Scan(&bytesIn, &bytesOut))
	assert.Equal(t, int64(totalInput), bytesIn)
	assert.Equal(t, int64(totalOutput), bytesOut)
}
