package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSQLReconciliationPreservesNewerPacket(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	old, err := UpsertFreeRADIUSAccountingRecord(context.Background(), FreeRADIUSAccountingRecord{
		AcctUniqueID: "revision-race", AcctSessionID: "revision-session", Username: "revision-user",
		AcctStartTime: now.Format(time.RFC3339), AcctUpdateTime: now.Format(time.RFC3339),
		AcctInputOctets: 100, AegisSource: "freeradius-sql",
	})
	require.NoError(t, err)
	queued, err := IngestAccountingEvent(context.Background(), FreeRADIUSAccountingEventFromRecord(old))
	require.NoError(t, err)
	// Deterministically inject the next packet between snapshot read and apply.
	newer := old
	newer.AcctUpdateTime = now.Add(time.Minute).Format(time.RFC3339)
	newer.AcctInputOctets, newer.AcctSessionTime = 500, 60
	newer, err = UpsertFreeRADIUSAccountingRecord(context.Background(), newer)
	require.NoError(t, err)
	require.Greater(t, newer.AegisIngestRevision, old.AegisIngestRevision)
	_, err = ApplyAccountingEventByID(context.Background(), queued.Event.EventID)
	require.NoError(t, err)
	applied, err := GetAccountingEventByEventID(queued.Event.EventID)
	require.NoError(t, err)
	require.NoError(t, projectFreeRADIUSAccountingMetadata(old, applied))
	require.NoError(t, markFreeRADIUSAccountingReconciled(old, "revision-session", "reconciled", "", ""))
	stillPending, err := GetFreeRADIUSAccountingByUniqueID("revision-race")
	require.NoError(t, err)
	require.Equal(t, uint64(500), stillPending.AcctInputOctets)
	require.Equal(t, newer.AegisIngestRevision, stillPending.AegisIngestRevision)
	require.Equal(t, "pending", stillPending.AegisReconcileStatus)
	require.Empty(t, stillPending.AegisLastCorrelationEventID)
	result, err := ReconcileFreeRADIUSAccounting(10)
	require.NoError(t, err)
	require.Equal(t, 0, result.ErrorCount)
	final, err := GetFreeRADIUSAccountingByUniqueID("revision-race")
	require.NoError(t, err)
	require.Equal(t, "reconciled", final.AegisReconcileStatus)
	require.Equal(t, newer.AegisIngestRevision, final.AegisIngestRevision)
	require.NotEmpty(t, final.AegisLastCorrelationEventID)
	var bytes int64
	require.NoError(t, DB.QueryRow("SELECT bytes_in FROM sessions WHERE id = ?", "revision-session").Scan(&bytes))
	require.Equal(t, int64(500), bytes)
}

func TestSQLIngestRevisionUpgradePreservesRows(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	_, err := DB.Exec("INSERT INTO radacct (acctsessionid, acctuniqueid, username) VALUES ('legacy', 'legacy', 'kept')")
	require.NoError(t, err)
	_, err = DB.Exec("ALTER TABLE radacct DROP COLUMN aegis_ingest_revision; ALTER TABLE radacct DROP COLUMN aegis_packet_source; DELETE FROM schema_version WHERE version = 103")
	require.NoError(t, err)
	require.NoError(t, Migrate())
	require.NoError(t, Migrate())
	record, err := GetFreeRADIUSAccountingByUniqueID("legacy")
	require.NoError(t, err)
	require.Equal(t, "kept", record.Username)
	require.Equal(t, int64(0), record.AegisIngestRevision)
	require.Empty(t, record.AegisPacketSource)
}

func TestSQLReconciliationPreservesProviderSourceAndNewerPacket(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	record, err := UpsertFreeRADIUSAccountingRecord(context.Background(), FreeRADIUSAccountingRecord{
		AcctUniqueID: "provider-snapshot", AcctSessionID: "provider-session", Username: "provider-user",
		AcctStartTime: now, AcctUpdateTime: now, AcctInputOctets: 100,
		AegisSource: "upstream-provider",
	})
	require.NoError(t, err)
	queued, err := IngestAccountingEvent(context.Background(), FreeRADIUSAccountingEventFromRecord(record))
	require.NoError(t, err)
	newer := record
	newer.AcctUpdateTime = time.Now().UTC().Add(time.Minute).Format(time.RFC3339)
	newer.AcctInputOctets, newer.AcctSessionTime = 500, 60
	newer, err = UpsertFreeRADIUSAccountingRecord(context.Background(), newer)
	require.NoError(t, err)
	_, err = applyAccountingEventByID(context.Background(), queued.Event.EventID, true)
	require.NoError(t, err)
	require.NoError(t, markFreeRADIUSAccountingReconciled(record, "provider-session", "reconciled", "", ""))
	pending, err := GetFreeRADIUSAccountingByUniqueID(record.AcctUniqueID)
	require.NoError(t, err)
	require.Equal(t, uint64(500), pending.AcctInputOctets)
	require.Equal(t, "pending", pending.AegisReconcileStatus)
	result, err := ReconcileFreeRADIUSAccounting(10)
	require.NoError(t, err)
	require.Zero(t, result.ErrorCount, result.LastError)
	stored, err := GetFreeRADIUSAccountingByUniqueID(record.AcctUniqueID)
	require.NoError(t, err)
	require.Equal(t, "reconciled", stored.AegisReconcileStatus)
	require.Equal(t, "upstream-provider", stored.AegisSource)
	require.Equal(t, newer.AegisIngestRevision, stored.AegisIngestRevision)
	require.Equal(t, uint64(500), stored.AcctInputOctets)
}
