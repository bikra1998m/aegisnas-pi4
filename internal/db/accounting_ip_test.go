package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountingIPAssignmentsLifecycle(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	ingested, err := IngestAccountingEvent(ctx, AccountingEventRecord{
		AcctUniqueID:        "ip-unique-1",
		AcctSessionID:       "ip-sess-1",
		SessionKey:          "ip-sess-1",
		StatusType:          "Start",
		EventTime:           now.Format(time.RFC3339Nano),
		Username:            "ivy",
		NASIPAddress:        "10.0.0.31",
		NASPortID:           "31",
		CallingStationID:    "00-11-22-33-44-99",
		FramedIPAddress:     "192.0.2.31",
		FramedIPv6Address:   "2001:db8::31",
		FramedIPv6Prefix:    "2001:db8:31::99/64",
		DelegatedIPv6Prefix: "2001:db8:3100::/56",
		FramedInterfaceID:   "ABCD:0000:0000:0031",
		FramedRoute:         "198.51.100.0/24 192.0.2.1",
		FramedIPv6Route:     "2001:db8:feed::/64 fe80::1",
		AcctSessionTime:     1,
		Source:              "packet-test",
	})
	require.NoError(t, err)
	assert.Equal(t, "ok", ingested.Event.IPAssignmentStatus)
	assert.Equal(t, "2001:db8:31::/64", ingested.Event.FramedIPv6Prefix)
	assert.Equal(t, "abcd:0000:0000:0031", ingested.Event.FramedInterfaceID)

	applied, err := ApplyAccountingEventByID(ctx, ingested.Event.EventID)
	require.NoError(t, err)
	assert.Equal(t, 1, applied.Applied)

	var ipv6Address, ipv6Prefix, delegatedPrefix, framedRoute, framedIPv6Route string
	require.NoError(t, DB.QueryRow(`SELECT COALESCE(ipv6_address, ''), COALESCE(framed_ipv6_prefix, ''),
		COALESCE(delegated_ipv6_prefix, ''), COALESCE(framed_route, ''),
		COALESCE(framed_ipv6_route, '') FROM sessions WHERE id = ?`, "ip-sess-1").Scan(
		&ipv6Address, &ipv6Prefix, &delegatedPrefix, &framedRoute, &framedIPv6Route))
	assert.Equal(t, "2001:db8::31", ipv6Address)
	assert.Equal(t, "2001:db8:31::/64", ipv6Prefix)
	assert.Equal(t, "2001:db8:3100::/56", delegatedPrefix)
	assert.Equal(t, "198.51.100.0/24 192.0.2.1", framedRoute)
	assert.Equal(t, "2001:db8:feed::/64 fe80::1", framedIPv6Route)

	var radacctRouteStatus, radacctIPv6Route string
	require.NoError(t, DB.QueryRow(`SELECT aegis_route_status, COALESCE(framedipv6route, '')
		FROM radacct WHERE acctuniqueid = ?`, "ip-unique-1").Scan(&radacctRouteStatus, &radacctIPv6Route))
	assert.Equal(t, "ok", radacctRouteStatus)
	assert.Equal(t, "2001:db8:feed::/64 fe80::1", radacctIPv6Route)

	stop, err := IngestAccountingEvent(ctx, AccountingEventRecord{
		AcctUniqueID:     "ip-unique-2",
		AcctSessionID:    "ip-sess-1",
		SessionKey:       "ip-sess-1",
		StatusType:       "Stop",
		EventTime:        now.Add(time.Minute).Format(time.RFC3339Nano),
		Username:         "ivy",
		NASIPAddress:     "10.0.0.31",
		NASPortID:        "31",
		CallingStationID: "00-11-22-33-44-99",
		AcctSessionTime:  60,
		Source:           "packet-test",
	})
	require.NoError(t, err)
	_, err = ApplyAccountingEventByID(ctx, stop.Event.EventID)
	require.NoError(t, err)

	summary, err := GetAccountingIPAssignmentSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.AssignmentRows)
	assert.Equal(t, 0, summary.ActiveAssignments)
	assert.Equal(t, 2, summary.ClosedAssignments)
	assert.Equal(t, 1, summary.IPv6AddressRows)
	assert.Equal(t, 1, summary.DelegatedPrefixRows)
	assert.Equal(t, 1, summary.IPv4RouteRows)
	assert.Equal(t, 1, summary.IPv6RouteRows)
	assert.Equal(t, 0, summary.InvalidRows)
}

func TestAccountingIPAssignmentsRecordInvalidRoutes(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	ingested, err := IngestAccountingEvent(context.Background(), AccountingEventRecord{
		AcctUniqueID:    "ip-invalid-1",
		AcctSessionID:   "ip-invalid-1",
		SessionKey:      "ip-invalid-1",
		StatusType:      "Interim-Update",
		EventTime:       time.Now().UTC().Format(time.RFC3339Nano),
		Username:        "jules",
		NASIPAddress:    "10.0.0.32",
		FramedIPv6Route: "not-a-prefix fe80::1",
		Source:          "packet-test",
	})
	require.NoError(t, err)
	assert.Equal(t, "invalid", ingested.Event.IPAssignmentStatus)
	assert.Contains(t, ingested.Event.IPAssignmentError, "Framed-IPv6-Route")

	_, err = ApplyAccountingEventByID(context.Background(), ingested.Event.EventID)
	require.NoError(t, err)

	stored, err := GetAccountingEventByEventID(ingested.Event.EventID)
	require.NoError(t, err)
	assert.Equal(t, "invalid", stored.IPAssignmentStatus)
	assert.Contains(t, stored.IPAssignmentError, "not-a-prefix")

	summary, err := GetAccountingIPAssignmentSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.InvalidRows)
}

func TestFreeRADIUSAccountingIPv6RouteReconcile(t *testing.T) {
	setupFreeRADIUSAccountingTestDB(t)
	now := time.Now().UTC()
	_, err := UpsertFreeRADIUSAccountingRecord(context.Background(), FreeRADIUSAccountingRecord{
		AcctSessionID:        "radacct-ipv6-1",
		AcctUniqueID:         "radacct-ipv6-1",
		Username:             "kai",
		NASIPAddress:         "10.0.0.33",
		NASPortID:            "33",
		AcctStartTime:        now.Add(-time.Minute).Format(time.RFC3339Nano),
		AcctUpdateTime:       now.Format(time.RFC3339Nano),
		FramedIPAddress:      "192.0.2.33",
		FramedIPv6Address:    "2001:db8::33",
		FramedIPv6Prefix:     "2001:db8:33::1/64",
		DelegatedIPv6Prefix:  "2001:db8:3300::/56",
		FramedRoute:          "203.0.113.0/24 192.0.2.1",
		FramedIPv6Route:      "2001:db8:3301::/64 fe80::1",
		AegisReconcileStatus: "pending",
	})
	require.NoError(t, err)

	result, err := ReconcileFreeRADIUSAccounting(10)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Reconciled)

	var ipv6Address, delegatedPrefix, framedIPv6Route string
	require.NoError(t, DB.QueryRow(`SELECT COALESCE(ipv6_address, ''),
		COALESCE(delegated_ipv6_prefix, ''), COALESCE(framed_ipv6_route, '')
		FROM sessions WHERE id = ?`, "radacct-ipv6-1").Scan(&ipv6Address, &delegatedPrefix, &framedIPv6Route))
	assert.Equal(t, "2001:db8::33", ipv6Address)
	assert.Equal(t, "2001:db8:3300::/56", delegatedPrefix)
	assert.Equal(t, "2001:db8:3301::/64 fe80::1", framedIPv6Route)

	summary, err := GetAccountingIPAssignmentSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.AssignmentRows)
	assert.Equal(t, 1, summary.RadAcctRowsWithIPv6)
	assert.Equal(t, 1, summary.SessionRowsWithRoute)
}
