package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateCompilerEvents(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "rate-compiler-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	eventID, err := RecordRateCompilerEvent(RateCompilerEventInput{
		Operation:        "compile",
		Status:           "compiled",
		PackKeysJSON:     `["mikrotik","ubnt"]`,
		DownloadRateKbps: 50000,
		UploadRateKbps:   20000,
		AttributeCount:   3,
		RequestJSON:      `{"download_rate_kbps":50000}`,
		ResponseJSON:     `{"status":"ready"}`,
		DiagnosticsJSON:  `[]`,
		Actor:            "ops",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListRateCompilerEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, eventID, events[0].EventID)
	assert.Equal(t, "compile", events[0].Operation)
	assert.Equal(t, "compiled", events[0].Status)
	assert.Equal(t, 3, events[0].AttributeCount)
	assert.Equal(t, "ops", events[0].Actor)

	decompileID, err := RecordRateCompilerEvent(RateCompilerEventInput{
		Operation:        "decompile",
		Status:           "decompiled",
		PackKeysJSON:     `["ubnt"]`,
		DownloadRateKbps: 50000,
		UploadRateKbps:   20000,
		AttributeCount:   2,
		RequestJSON:      `{"pack_key":"ubnt"}`,
		ResponseJSON:     `{"status":"ready"}`,
		DiagnosticsJSON:  `[]`,
		Actor:            "ops",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, decompileID)

	summary, err := GetRateCompilerEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.CompiledCount)
	assert.Equal(t, 1, summary.DecompiledCount)
}
