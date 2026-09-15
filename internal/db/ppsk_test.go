package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPPSKLifecycleEventRecordListSummary(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordPPSKLifecycleEvent(PPSKLifecycleEventInput{
		Operation:              "preview",
		Status:                 "previewed",
		ConfigPath:             "/tmp/hostapd.conf",
		PSKFilePath:            "/tmp/aegisnas-ppsk.psk",
		HostapdConfigSHA256:    "sha256:hostapd",
		PSKFileSHA256:          "sha256:psk",
		PlanFingerprint:        "sha256:plan",
		SSIDCount:              1,
		PPSKSSIDCount:          1,
		ProfileCount:           1,
		GroupCount:             1,
		CredentialCount:        2,
		ActiveCredentialCount:  1,
		StagedCredentialCount:  1,
		RevokedCredentialCount: 1,
		ExpiredCredentialCount: 0,
		ControllerSyncCount:    1,
		DiagnosticCount:        0,
		SummaryJSON:            `{"ppsk_ssid_count":1}`,
		ReportJSON:             `{"feature_id":"NAS-0077"}`,
		Actor:                  "ops",
	})
	require.NoError(t, err)
	require.NotEmpty(t, eventID)

	events, err := ListPPSKLifecycleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, eventID, events[0].EventID)
	assert.Equal(t, 1, events[0].PPSKSSIDCount)
	assert.Equal(t, 1, events[0].ControllerSyncCount)

	summary, err := GetPPSKLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.PreviewEvents)
	assert.Equal(t, 1, summary.PreviewedCount)
	assert.Equal(t, "sha256:plan", summary.LastFingerprint)
	assert.Equal(t, "sha256:psk", summary.LastPSKFileSHA256)
	assert.Equal(t, 1, summary.LastPPSKSSIDCount)
	assert.Equal(t, 1, summary.LastControllerSyncCount)
}
