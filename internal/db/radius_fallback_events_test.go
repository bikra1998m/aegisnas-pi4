package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRadiusFallbackEventsRoundTripAndSummary(t *testing.T) {
	setupRadiusFallbackEventDB(t)

	require.NoError(t, RecordRadiusFallbackEvent(RadiusFallbackEvent{
		ObservedAt:     "2026-06-01T10:00:00Z",
		Source:         "portal",
		UsernameHash:   "hash-a",
		Realm:          "guest.example.com",
		IdentitySource: "local",
		Role:           "guest-basic",
		Decision:       "allowed",
		Reason:         "fallback policy permits this identity",
		UpstreamStatus: "down",
		PolicyMode:     "enforce",
		FailClosed:     true,
	}, map[string]any{"upstream_message": "timeout"}, 10))
	require.NoError(t, RecordRadiusFallbackEvent(RadiusFallbackEvent{
		ObservedAt:     "2026-06-01T10:05:00Z",
		Source:         "portal",
		UsernameHash:   "hash-b",
		Decision:       "denied",
		Reason:         "identity is not in the fallback allowlist",
		UpstreamStatus: "down",
		PolicyMode:     "enforce",
		FailClosed:     true,
	}, nil, 10))

	events, err := ListRadiusFallbackEvents("", "portal", 10)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "denied", events[0].Decision)
	assert.Equal(t, "hash-b", events[0].UsernameHash)
	assert.NotContains(t, events[0].DetailsJSON, "alice")

	allowed, err := ListRadiusFallbackEvents("allowed", "", 10)
	require.NoError(t, err)
	require.Len(t, allowed, 1)
	assert.Contains(t, allowed[0].DetailsJSON, "timeout")

	summary, err := GetRadiusFallbackEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalRecords)
	assert.Equal(t, 1, summary.AllowedCount)
	assert.Equal(t, 1, summary.DeniedCount)
	assert.Equal(t, "denied", summary.LastDecision)
}

func TestRadiusFallbackEventRetention(t *testing.T) {
	setupRadiusFallbackEventDB(t)
	require.NoError(t, RecordRadiusFallbackEvent(RadiusFallbackEvent{ObservedAt: "2026-06-01T10:00:00Z", Source: "portal", UsernameHash: "hash-a", Decision: "allowed", Reason: "ok", PolicyMode: "monitor"}, nil, 1))
	require.NoError(t, RecordRadiusFallbackEvent(RadiusFallbackEvent{ObservedAt: "2026-06-01T10:01:00Z", Source: "portal", UsernameHash: "hash-b", Decision: "denied", Reason: "blocked", PolicyMode: "enforce"}, nil, 1))

	events, err := ListRadiusFallbackEvents("", "", 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "hash-b", events[0].UsernameHash)
}

func setupRadiusFallbackEventDB(t *testing.T) {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "radius-fallback-events-*.db")
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
