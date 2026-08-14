package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVLANPolicyEventSummary(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	firstID, err := RecordVLANPolicyEvent(VLANPolicyEventInput{
		Operation:       "compile",
		Status:          "compiled",
		Role:            "voice-device",
		PoolName:        "branch-data",
		EffectiveVLAN:   21,
		DataVLAN:        21,
		VoiceVLAN:       30,
		TaggedVLANCount: 2,
		QinQOuterVLAN:   3000,
		QinQInnerVLAN:   21,
		FallbackVLAN:    99,
		AuthFailVLAN:    98,
		AttributeCount:  10,
		DiagnosticCount: 1,
		Fingerprint:     "sha256:first",
		RequestJSON:     "{}",
		ResponseJSON:    "{}",
		DiagnosticsJSON: "[]",
		Actor:           "ops",
	})
	require.NoError(t, err)
	require.NotEmpty(t, firstID)
	_, err = RecordVLANPolicyEvent(VLANPolicyEventInput{
		Operation:       "preview",
		Status:          "blocked",
		Role:            "broken",
		DiagnosticCount: 2,
		RequestJSON:     "{}",
		ResponseJSON:    "{}",
		DiagnosticsJSON: "[]",
	})
	require.NoError(t, err)

	events, err := ListVLANPolicyEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "broken", events[0].Role)
	assert.Equal(t, "voice-device", events[1].Role)
	assert.Equal(t, 21, events[1].EffectiveVLAN)
	assert.Equal(t, 3000, events[1].QinQOuterVLAN)

	summary, err := GetVLANPolicyEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.CompiledCount)
	assert.Equal(t, 1, summary.BlockedCount)
	assert.Equal(t, "blocked", summary.LastStatus)
}
