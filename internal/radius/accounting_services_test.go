package radius

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestProcessAccountingMirrorsMultiServiceCorrelation(t *testing.T) {
	setupSQLAccountingDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	rec := &AccountingRecord{
		SessionID:          "radius-service-child",
		Username:           "dana",
		NASIPAddress:       "10.0.0.47",
		NASPort:            47,
		AcctStatusType:     "Interim-Update",
		AcctMultiSessionID: "radius-service-parent",
		AcctLinkCount:      2,
		AcctInputOctets:    65536,
		AcctOutputOctets:   131072,
		AcctSessionTime:    90,
		CalledStationID:    "bng-1",
		CallingStationID:   "00-11-22-33-44-bb",
		ServiceType:        "Framed-User",
		FramedProtocol:     "PPP",
		RadiusClass:        "service_key=data;service_leg_id=ppp-access",
		Timestamp:          now,
	}
	require.NoError(t, ProcessAccounting(rec))

	summary, err := db.GetAccountingServiceCorrelationSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.CorrelationRows)
	assert.Equal(t, 1, summary.ActiveCorrelations)
	assert.Equal(t, 1, summary.DataServices)
	assert.Equal(t, 1, summary.AcctMultiSessionRows)

	uniqueID := db.FreeRADIUSAcctUniqueID("radius-service-child", "dana", "10.0.0.47", "47", "00-11-22-33-44-bb")
	radacct, err := db.GetFreeRADIUSAccountingByUniqueID(uniqueID)
	require.NoError(t, err)
	assert.Equal(t, "radius-service-parent", radacct.AcctMultiSessionID)
	assert.Equal(t, int64(2), radacct.AcctLinkCount)
	assert.Equal(t, "radius-service-parent", radacct.AegisParentSessionID)
	assert.Equal(t, "data", radacct.AegisServiceKey)
	assert.Equal(t, "data", radacct.AegisServiceCategory)
	assert.Equal(t, "ppp-access", radacct.AegisServiceLegID)
	assert.Equal(t, "active", radacct.AegisCorrelationStatus)
	assert.NotEmpty(t, radacct.AegisCorrelationID)

	report := BuildAccountingServicesReport(&config.Config{
		Radius: config.RadiusConfig{
			AccountingServices: config.RadiusAccountingServicesConfig{
				Enabled:                      true,
				CorrelateSubscriberChains:    true,
				DeriveFromClass:              true,
				DeriveFromAcctMultiSessionID: true,
				RetainUnmatched:              true,
				RetentionDays:                365,
				MaxRecentServices:            10,
			},
		},
	})
	assert.True(t, report.Enabled)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 1, report.Summary.CorrelationRows)
	require.Len(t, report.Recent, 1)
	assert.Equal(t, radacct.AegisCorrelationID, report.Recent[0].CorrelationID)
	assert.Contains(t, report.Attributes, "Acct-Multi-Session-Id")
}

func TestBuildAccountingServicesReportDetectsConflicts(t *testing.T) {
	setupSQLAccountingDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, ProcessAccounting(&AccountingRecord{
		SessionID:          "radius-conflict-child",
		Username:           "erin",
		NASIPAddress:       "10.0.0.48",
		AcctStatusType:     "Start",
		AcctMultiSessionID: "radius-conflict-a",
		ServiceKey:         "data",
		Timestamp:          now,
	}))
	require.NoError(t, ProcessAccounting(&AccountingRecord{
		SessionID:          "radius-conflict-child",
		Username:           "erin",
		NASIPAddress:       "10.0.0.48",
		AcctStatusType:     "Interim-Update",
		AcctMultiSessionID: "radius-conflict-b",
		ServiceKey:         "data",
		AcctInputOctets:    10,
		AcctOutputOctets:   20,
		Timestamp:          now.Add(time.Minute),
	}))

	report := BuildAccountingServicesReport(&config.Config{
		Radius: config.RadiusConfig{
			AccountingServices: config.RadiusAccountingServicesConfig{
				Enabled:                      true,
				CorrelateSubscriberChains:    true,
				DeriveFromClass:              true,
				DeriveFromAcctMultiSessionID: true,
				RetentionDays:                365,
				MaxRecentServices:            10,
			},
		},
	})
	assert.Equal(t, "degraded", report.Status)
	assert.Equal(t, 1, report.Summary.ConflictCorrelations)
	assert.Contains(t, report.Message, "conflict")
}
