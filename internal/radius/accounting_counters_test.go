package radius

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestBuildAccountingCountersReport(t *testing.T) {
	setupSQLAccountingDB(t)
	cfg := accountingCountersTestConfig()
	_, err := db.IngestAccountingEvent(context.Background(), db.AccountingEventRecord{
		AcctUniqueID:        "counter-report-1",
		AcctSessionID:       "counter-report-1",
		SessionKey:          "counter-report-1",
		StatusType:          "Interim-Update",
		EventTime:           time.Now().UTC().Format(time.RFC3339Nano),
		Username:            "pat",
		NASIPAddress:        "10.0.0.23",
		NASPortID:           "21",
		AcctInputOctets:     9,
		AcctInputGigawords:  1,
		AcctOutputOctets:    10,
		AcctOutputGigawords: 1,
		Source:              "unit-test",
	})
	require.NoError(t, err)
	applied, err := db.ApplyPendingAccountingEvents(context.Background(), 10)
	require.NoError(t, err)
	assert.Equal(t, 1, applied.Applied)

	report := BuildAccountingCountersReport(cfg)
	assert.True(t, report.Enabled)
	assert.Equal(t, "ready", report.Status)
	assert.Contains(t, report.Attributes, "Acct-Input-Gigawords")
	assert.Contains(t, report.RFCs, "RFC 2866")
	assert.Equal(t, 1, report.Summary.EventRows)
	assert.Equal(t, 1, report.Summary.RolloverEvents)

	cfg.Radius.AccountingCounters.GigawordsEnabled = false
	report = BuildAccountingCountersReport(cfg)
	assert.Equal(t, "degraded", report.Status)
}

func accountingCountersTestConfig() *config.Config {
	cfg := accountingOrderingTestConfig()
	cfg.Radius.AccountingCounters = config.RadiusAccountingCountersConfig{
		Enabled:               true,
		GigawordsEnabled:      true,
		ResetDetectionEnabled: true,
		MaxCounterBits:        64,
		OverflowPolicy:        "saturate",
		RetentionDays:         30,
	}
	return cfg
}
