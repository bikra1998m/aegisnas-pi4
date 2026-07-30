package radius

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestProcessAccountingMirrorsIPv6AndRoutes(t *testing.T) {
	setupSQLAccountingDB(t)
	rec := &AccountingRecord{
		SessionID:           "radius-ip-1",
		Username:            "lina",
		NASIPAddress:        "10.0.0.41",
		NASPort:             41,
		AcctStatusType:      "Interim-Update",
		CalledStationID:     "ap-ip",
		CallingStationID:    "00-11-22-33-44-aa",
		FramedIPAddress:     "192.0.2.41",
		FramedIPv6Address:   "2001:db8::41",
		FramedIPv6Prefix:    "2001:db8:41::8/64",
		DelegatedIPv6Prefix: "2001:db8:4100::/56",
		FramedInterfaceID:   "ABCD:0000:0000:0041",
		FramedRoute:         "198.51.100.0/24 192.0.2.1",
		FramedIPv6Route:     "2001:db8:4101::/64 fe80::1",
		AcctInputOctets:     1024,
		AcctOutputOctets:    2048,
		AcctSessionTime:     30,
		Timestamp:           time.Now().UTC(),
	}
	require.NoError(t, ProcessAccounting(rec))

	uniqueID := db.FreeRADIUSAcctUniqueID("radius-ip-1", "lina", "10.0.0.41", "41", "00-11-22-33-44-aa")
	radacct, err := db.GetFreeRADIUSAccountingByUniqueID(uniqueID)
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::41", radacct.FramedIPv6Address)
	assert.Equal(t, "2001:db8:41::/64", radacct.FramedIPv6Prefix)
	assert.Equal(t, "2001:db8:4100::/56", radacct.DelegatedIPv6Prefix)
	assert.Equal(t, "2001:db8:4101::/64 fe80::1", radacct.FramedIPv6Route)
	assert.Equal(t, "ok", radacct.AegisRouteStatus)

	report := BuildAccountingIPReport(&config.Config{
		Radius: config.RadiusConfig{
			AccountingIP: config.RadiusAccountingIPConfig{
				Enabled:                true,
				IPv6Enabled:            true,
				RouteAccountingEnabled: true,
				DelegatedPrefixEnabled: true,
				RetentionDays:          365,
			},
		},
	})
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 1, report.Summary.AssignmentRows)
	assert.Equal(t, 1, report.Summary.IPv6AddressRows)
	assert.Equal(t, 1, report.Summary.IPv6RouteRows)
}

func TestBuildAccountingIPReportDetectsInvalidEvidence(t *testing.T) {
	setupSQLAccountingDB(t)
	_, err := db.IngestAccountingEvent(t.Context(), db.AccountingEventRecord{
		AcctUniqueID:    "radius-ip-invalid-1",
		AcctSessionID:   "radius-ip-invalid-1",
		SessionKey:      "radius-ip-invalid-1",
		StatusType:      "Interim-Update",
		EventTime:       time.Now().UTC().Format(time.RFC3339Nano),
		Username:        "mika",
		NASIPAddress:    "10.0.0.42",
		FramedIPv6Route: "bad-route fe80::1",
		Source:          "test",
	})
	require.NoError(t, err)
	_, err = db.ApplyPendingAccountingEvents(t.Context(), 10)
	require.NoError(t, err)

	report := BuildAccountingIPReport(&config.Config{
		Radius: config.RadiusConfig{
			AccountingIP: config.RadiusAccountingIPConfig{
				Enabled:                true,
				IPv6Enabled:            true,
				RouteAccountingEnabled: true,
				DelegatedPrefixEnabled: true,
				RejectInvalid:          true,
				RetentionDays:          365,
			},
		},
	})
	assert.Equal(t, "degraded", report.Status)
	assert.Equal(t, 1, report.Summary.InvalidRows)
	assert.NotEmpty(t, report.Warnings)
}
