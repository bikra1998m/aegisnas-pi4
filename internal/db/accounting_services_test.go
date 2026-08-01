package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountingServiceCorrelationLinksSubscriberServiceChain(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	chain, err := ActivateSubscriberServiceChain(SubscriberServiceActivationRequest{
		SessionID:        "parent-svc-1",
		Username:         "alice@example.com",
		CallingStationID: "00-11-22-33-44-55",
		Tenant:           "corp",
		PolicySetHash:    strings.Repeat("a", 64),
		RequestHash:      strings.Repeat("b", 64),
		ServiceChainHash: strings.Repeat("c", 64),
		ServiceCount:     2,
		RequiredCount:    2,
		DecisionJSON:     `{"allow":true}`,
		ServicesJSON:     `[{"key":"data","type":"data","sequence":10,"accounting_class":"internet"},{"key":"voice","type":"voice","sequence":20,"accounting_class":"voice"}]`,
		Actor:            "policy-engine",
		StartedAt:        now.Add(-time.Minute),
	})
	require.NoError(t, err)
	assert.Equal(t, SubscriberServiceChainStatusActive, chain.Status)

	start, err := IngestAccountingEvent(ctx, AccountingEventRecord{
		AcctUniqueID:       "svc-unique-1",
		AcctSessionID:      "child-svc-1",
		SessionKey:         "child-svc-1",
		StatusType:         "Start",
		AcctMultiSessionID: "parent-svc-1",
		AcctLinkCount:      2,
		EventTime:          now.Format(time.RFC3339Nano),
		Username:           "alice@example.com",
		NASIPAddress:       "10.0.0.44",
		NASPortID:          "44",
		CallingStationID:   "00-11-22-33-44-55",
		ServiceType:        "Framed-User",
		FramedProtocol:     "PPP",
		Class:              "service_key=data;accounting_class=internet",
		Source:             "packet-test",
	})
	require.NoError(t, err)
	applied, err := ApplyAccountingEventByID(ctx, start.Event.EventID)
	require.NoError(t, err)
	assert.Equal(t, 1, applied.Applied)

	correlation, err := GetAccountingServiceCorrelation(start.Event.CorrelationID)
	require.NoError(t, err)
	assert.Equal(t, "parent-svc-1", correlation.ParentSessionKey)
	assert.Equal(t, "child-svc-1", correlation.ChildSessionKey)
	assert.Equal(t, "data", correlation.ServiceKey)
	assert.Equal(t, "data", correlation.ServiceCategory)
	assert.Equal(t, chain.ChainID, correlation.LinkedChainID)
	assert.Equal(t, "data", correlation.LinkedServiceKey)
	assert.Equal(t, "active", correlation.CorrelationStatus)
	assert.Contains(t, correlation.CorrelationSource, "subscriber-service-chain")

	interim, err := IngestAccountingEvent(ctx, AccountingEventRecord{
		AcctUniqueID:       "svc-unique-1",
		AcctSessionID:      "child-svc-1",
		SessionKey:         "child-svc-1",
		StatusType:         "Interim-Update",
		AcctMultiSessionID: "parent-svc-1",
		AcctLinkCount:      2,
		EventTime:          now.Add(time.Minute).Format(time.RFC3339Nano),
		Username:           "alice@example.com",
		NASIPAddress:       "10.0.0.44",
		NASPortID:          "44",
		CallingStationID:   "00-11-22-33-44-55",
		ServiceKey:         "data",
		ServiceType:        "Framed-User",
		FramedProtocol:     "PPP",
		AcctInputOctets:    5000,
		AcctOutputOctets:   7000,
		AcctSessionTime:    60,
		Class:              "accounting_class=internet",
		Source:             "packet-test",
	})
	require.NoError(t, err)
	_, err = ApplyAccountingEventByID(ctx, interim.Event.EventID)
	require.NoError(t, err)

	correlation, err = GetAccountingServiceCorrelation(start.Event.CorrelationID)
	require.NoError(t, err)
	assert.Equal(t, interim.Event.EventID, correlation.LastEventID)
	assert.Equal(t, "5000", correlation.InputOctets64)
	assert.Equal(t, "7000", correlation.OutputOctets64)

	var serviceStatus string
	var inputOctets, outputOctets int64
	var interimCount int
	require.NoError(t, DB.QueryRow(`SELECT status, input_octets, output_octets, interim_count
		FROM subscriber_service_accounting WHERE chain_id = ? AND service_key = ?`,
		chain.ChainID, "data").Scan(&serviceStatus, &inputOctets, &outputOctets, &interimCount))
	assert.Equal(t, "interim", serviceStatus)
	assert.Equal(t, int64(5000), inputOctets)
	assert.Equal(t, int64(7000), outputOctets)
	assert.Equal(t, 1, interimCount)

	stop, err := IngestAccountingEvent(ctx, AccountingEventRecord{
		AcctUniqueID:       "svc-unique-1",
		AcctSessionID:      "child-svc-1",
		SessionKey:         "child-svc-1",
		StatusType:         "Stop",
		AcctMultiSessionID: "parent-svc-1",
		AcctLinkCount:      2,
		EventTime:          now.Add(2 * time.Minute).Format(time.RFC3339Nano),
		Username:           "alice@example.com",
		NASIPAddress:       "10.0.0.44",
		NASPortID:          "44",
		CallingStationID:   "00-11-22-33-44-55",
		ServiceKey:         "data",
		ServiceType:        "Framed-User",
		FramedProtocol:     "PPP",
		AcctInputOctets:    8000,
		AcctOutputOctets:   9000,
		AcctSessionTime:    120,
		AcctTerminateCause: "User-Request",
		Class:              "accounting_class=internet",
		Source:             "packet-test",
	})
	require.NoError(t, err)
	_, err = ApplyAccountingEventByID(ctx, stop.Event.EventID)
	require.NoError(t, err)

	correlation, err = GetAccountingServiceCorrelation(start.Event.CorrelationID)
	require.NoError(t, err)
	assert.Equal(t, "closed", correlation.CorrelationStatus)
	assert.NotEmpty(t, correlation.StoppedAt)

	summary, err := GetAccountingServiceCorrelationSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.CorrelationRows)
	assert.Equal(t, 0, summary.ActiveCorrelations)
	assert.Equal(t, 1, summary.ClosedCorrelations)
	assert.Equal(t, 1, summary.LinkedSubscriberServices)
	assert.Equal(t, 1, summary.DataServices)
	assert.Equal(t, 1, summary.AcctMultiSessionRows)

	require.NoError(t, DB.QueryRow(`SELECT status, input_octets, output_octets, interim_count
		FROM subscriber_service_accounting WHERE chain_id = ? AND service_key = ?`,
		chain.ChainID, "data").Scan(&serviceStatus, &inputOctets, &outputOctets, &interimCount))
	assert.Equal(t, "stopped", serviceStatus)
	assert.Equal(t, int64(8000), inputOctets)
	assert.Equal(t, int64(9000), outputOctets)
	assert.Equal(t, 1, interimCount)

	radacct, err := GetFreeRADIUSAccountingByUniqueID("svc-unique-1")
	require.NoError(t, err)
	assert.Equal(t, correlation.CorrelationID, radacct.AegisCorrelationID)
	assert.Equal(t, "closed", radacct.AegisCorrelationStatus)
	assert.Equal(t, "data", radacct.AegisServiceKey)
	assert.Equal(t, "parent-svc-1", radacct.AegisParentSessionID)
	assert.Equal(t, stop.Event.EventID, radacct.AegisLastCorrelationEventID)
}

func TestAccountingServiceCorrelationDetectsConflictingChildSession(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	first, err := IngestAccountingEvent(ctx, AccountingEventRecord{
		AcctUniqueID:       "svc-conflict-1",
		AcctSessionID:      "child-conflict-1",
		SessionKey:         "child-conflict-1",
		StatusType:         "Start",
		AcctMultiSessionID: "parent-a",
		EventTime:          now.Format(time.RFC3339Nano),
		Username:           "bob",
		NASIPAddress:       "10.0.0.45",
		ServiceKey:         "data",
		Source:             "packet-test",
	})
	require.NoError(t, err)
	_, err = ApplyAccountingEventByID(ctx, first.Event.EventID)
	require.NoError(t, err)

	second, err := IngestAccountingEvent(ctx, AccountingEventRecord{
		AcctUniqueID:       "svc-conflict-2",
		AcctSessionID:      "child-conflict-1",
		SessionKey:         "child-conflict-1",
		StatusType:         "Interim-Update",
		AcctMultiSessionID: "parent-b",
		EventTime:          now.Add(time.Minute).Format(time.RFC3339Nano),
		Username:           "bob",
		NASIPAddress:       "10.0.0.45",
		ServiceKey:         "data",
		AcctInputOctets:    10,
		AcctOutputOctets:   20,
		Source:             "packet-test",
	})
	require.NoError(t, err)
	_, err = ApplyAccountingEventByID(ctx, second.Event.EventID)
	require.NoError(t, err)

	summary, err := GetAccountingServiceCorrelationSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.CorrelationRows)
	assert.Equal(t, 1, summary.ActiveCorrelations)
	assert.Equal(t, 1, summary.ConflictCorrelations)
	assert.Contains(t, summary.LastCorrelationError, "already has active correlation")

	conflicts, err := ListAccountingServiceCorrelations(10, "conflict", "")
	require.NoError(t, err)
	require.Len(t, conflicts, 1)
	assert.Equal(t, "parent-b", conflicts[0].ParentSessionKey)
	assert.Contains(t, conflicts[0].CorrelationError, "parent-a")
}

func TestFreeRADIUSAccountingServiceCorrelationReconcile(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	_, err := UpsertFreeRADIUSAccountingRecord(context.Background(), FreeRADIUSAccountingRecord{
		AcctSessionID:        "radacct-service-child",
		AcctUniqueID:         "radacct-service-unique",
		AcctMultiSessionID:   "radacct-service-parent",
		AcctLinkCount:        3,
		Username:             "carol",
		NASIPAddress:         "10.0.0.46",
		NASPortID:            "46",
		AcctStartTime:        now.Add(-time.Minute).Format(time.RFC3339Nano),
		AcctUpdateTime:       now.Format(time.RFC3339Nano),
		AcctInputOctets:      4096,
		AcctOutputOctets:     8192,
		ServiceType:          "Framed-User",
		FramedProtocol:       "PPP",
		Class:                `{"service_key":"data","parent_session_key":"radacct-service-parent","service_leg_id":"ppp-1"}`,
		AegisReconcileStatus: "pending",
	})
	require.NoError(t, err)

	result, err := ReconcileFreeRADIUSAccounting(10)
	require.NoError(t, err)
	assert.Equal(t, "ok", result.Status)
	assert.Equal(t, 1, result.Reconciled)

	summary, err := GetAccountingServiceCorrelationSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.CorrelationRows)
	assert.Equal(t, 1, summary.ActiveCorrelations)
	assert.Equal(t, 1, summary.DataServices)
	assert.Equal(t, 1, summary.AcctMultiSessionRows)

	radacct, err := GetFreeRADIUSAccountingByUniqueID("radacct-service-unique")
	require.NoError(t, err)
	assert.Equal(t, "radacct-service-parent", radacct.AegisParentSessionID)
	assert.Equal(t, "data", radacct.AegisServiceKey)
	assert.Equal(t, "data", radacct.AegisServiceCategory)
	assert.Equal(t, "ppp-1", radacct.AegisServiceLegID)
	assert.Equal(t, "active", radacct.AegisCorrelationStatus)
	assert.NotEmpty(t, radacct.AegisCorrelationID)
	assert.NotEmpty(t, radacct.AegisLastCorrelationEventID)
}
