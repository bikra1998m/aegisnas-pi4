package db

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountingChargingProjectionRatingExportAndIntegrity(t *testing.T) {
	setupAccountingChargingDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	start := AccountingEventRecord{
		AcctUniqueID:     "charge-unique-1",
		AcctSessionID:    "charge-session-1",
		SessionKey:       "charge-session-1",
		StatusType:       "Start",
		EventTime:        now.Add(-10 * time.Minute).Format(time.RFC3339Nano),
		Username:         "alice@example.com",
		NASIPAddress:     "10.0.0.41",
		NASPortID:        "41",
		CallingStationID: "00-11-22-33-44-41",
		ServiceType:      "Framed-User",
		Class:            "service_key=internet;service_category=data;service_leg_id=ppp-1",
		Source:           "unit-test",
	}
	ingested, err := IngestAccountingEvent(ctx, start)
	require.NoError(t, err)
	_, err = ApplyAccountingEventByID(ctx, ingested.Event.EventID)
	require.NoError(t, err)

	stop := start
	stop.StatusType = "Stop"
	stop.EventTime = now.Format(time.RFC3339Nano)
	stop.AcctInputOctets = 1 << 30
	stop.AcctOutputOctets = 2 << 30
	stop.AcctSessionTime = 600
	stop.AcctTerminateCause = "User-Request"
	ingestedStop, err := IngestAccountingEvent(ctx, stop)
	require.NoError(t, err)
	_, err = ApplyAccountingEventByID(ctx, ingestedStop.Event.EventID)
	require.NoError(t, err)

	records, err := ListAccountingChargingRecords(AccountingChargingRecordQuery{Limit: 10})
	require.NoError(t, err)
	require.Len(t, records, 1)
	cdr := records[0]
	assert.Equal(t, AccountingChargingStatusClosed, cdr.Status)
	assert.Equal(t, AccountingChargingRatingUnrated, cdr.RatingStatus)
	assert.Equal(t, "internet", cdr.ServiceKey)
	assert.Equal(t, int64(600), cdr.DurationSeconds)
	assert.Equal(t, "1073741824", cdr.InputOctets64)
	assert.Equal(t, "2147483648", cdr.OutputOctets64)
	assert.NotContains(t, cdr.UsernameHash, "alice")
	assert.NotEmpty(t, cdr.IntegritySHA256)

	rated, err := RateAccountingChargingRecords(ctx, AccountingChargingRatingPolicy{
		RatingEnabled:        true,
		DefaultPlan:          "standard",
		Currency:             "USD",
		InputMicrosPerGiB:    1000000,
		OutputMicrosPerGiB:   2000000,
		SessionMicrosPerHour: 3600000,
		MinimumChargeMicros:  1,
	}, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, rated)

	cdr, err = GetAccountingChargingRecordByCDRID(cdr.CDRID)
	require.NoError(t, err)
	assert.Equal(t, AccountingChargingRatingRated, cdr.RatingStatus)
	assert.Equal(t, int64(5600000), cdr.RatedAmountMicros)
	assert.Contains(t, cdr.ChargeableUnitsJSON, "input_charge_micros")

	export, err := ExportAccountingChargingRecords(ctx, "jsonl", 10, "unit-test")
	require.NoError(t, err)
	assert.Equal(t, "complete", export.Status)
	assert.Equal(t, 1, export.RecordCount)
	assert.NotEmpty(t, export.PayloadSHA256)
	assert.NotEmpty(t, export.ManifestSHA256)

	storedExport, err := GetAccountingChargingExport(export.ExportID)
	require.NoError(t, err)
	assert.Contains(t, storedExport.Payload, cdr.CDRID)
	assert.True(t, strings.HasSuffix(storedExport.Payload, "\n"))

	cdr, err = GetAccountingChargingRecordByCDRID(cdr.CDRID)
	require.NoError(t, err)
	assert.Equal(t, AccountingChargingExportExported, cdr.ExportStatus)
	assert.Equal(t, export.ExportID, cdr.ExportBatchID)

	mismatches, err := VerifyAccountingChargingIntegrity(100)
	require.NoError(t, err)
	assert.Equal(t, 0, mismatches)

	_, err = DB.Exec(`UPDATE radius_accounting_charging_records SET rated_amount_micros = rated_amount_micros + 1 WHERE cdr_id = ?`, cdr.CDRID)
	require.NoError(t, err)
	mismatches, err = VerifyAccountingChargingIntegrity(100)
	require.NoError(t, err)
	assert.Equal(t, 1, mismatches)
}

func TestAccountingChargingLateCorrectionReturnsExportPending(t *testing.T) {
	setupAccountingChargingDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	event := AccountingEventRecord{
		AcctUniqueID:     "charge-late-1",
		AcctSessionID:    "charge-late-1",
		SessionKey:       "charge-late-1",
		StatusType:       "Stop",
		EventTime:        now.Format(time.RFC3339Nano),
		Username:         "late@example.com",
		NASIPAddress:     "10.0.0.42",
		NASPortID:        "42",
		CallingStationID: "00-11-22-33-44-42",
		AcctInputOctets:  100,
		AcctOutputOctets: 200,
		AcctSessionTime:  60,
		Source:           "unit-test",
	}
	ingested, err := IngestAccountingEvent(ctx, event)
	require.NoError(t, err)
	_, err = ApplyAccountingEventByID(ctx, ingested.Event.EventID)
	require.NoError(t, err)
	_, err = RateAccountingChargingRecords(ctx, AccountingChargingRatingPolicy{RatingEnabled: true, DefaultPlan: "standard", Currency: "USD"}, 10)
	require.NoError(t, err)
	export, err := ExportAccountingChargingRecords(ctx, "csv", 10, "unit-test")
	require.NoError(t, err)
	assert.Equal(t, "complete", export.Status)

	cdrID := AccountingChargingCDRID(event)
	_, err = DB.Exec(`UPDATE radius_accounting_charging_records
		SET export_status = 'exported', export_batch_id = ?, export_sha256 = ?, exported_at = ?, input_octets_64 = '100', total_octets_64 = '300'
		WHERE cdr_id = ?`, export.ExportID, export.PayloadSHA256, now.Format(time.RFC3339Nano), cdrID)
	require.NoError(t, err)
	event.EventID = ""
	event.AcctUniqueID = "charge-late-1-correction"
	event.AcctInputOctets = 500
	_, err = ProjectAccountingChargingRecord(ctx, event)
	require.NoError(t, err)
	record, err := GetAccountingChargingRecordByCDRID(cdrID)
	require.NoError(t, err)
	assert.Equal(t, AccountingChargingExportPending, record.ExportStatus)
	assert.Empty(t, record.ExportBatchID)
	assert.Equal(t, AccountingChargingRatingUnrated, record.RatingStatus)
}

func setupAccountingChargingDB(t *testing.T) {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "accounting-charging-*.db")
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
