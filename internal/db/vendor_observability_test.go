package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordVendorObservabilityAggregatesAndScores(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "vendor-observability-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	require.NoError(t, RecordVendorObservability(VendorObservabilityDelta{
		VendorKey:                 "Aruba",
		NASType:                   "controller",
		AuthSuccessDelta:          2,
		AuthFailureDelta:          1,
		VSAParsedDelta:            2,
		UnsupportedAttributeDelta: 1,
		Message:                   "auth response Access-Accept",
	}))
	require.NoError(t, RecordVendorObservability(VendorObservabilityDelta{
		VendorKey:       "aruba",
		NASType:         "controller",
		CoASuccessDelta: 1,
	}))
	require.NoError(t, RecordVendorObservability(VendorObservabilityDelta{
		VendorKey:       "cisco",
		NASType:         "switch",
		CoAFailureDelta: 1,
	}))

	records, err := ListVendorObservability(10)
	require.NoError(t, err)
	require.Len(t, records, 2)

	byVendor := map[string]VendorObservabilityRecord{}
	for _, item := range records {
		byVendor[item.VendorKey] = item
	}
	assert.Equal(t, 2, byVendor["aruba"].AuthSuccessCount)
	assert.Equal(t, 1, byVendor["aruba"].AuthFailureCount)
	assert.Equal(t, 2, byVendor["aruba"].VSAParsedCount)
	assert.Equal(t, 1, byVendor["aruba"].UnsupportedAttributeCount)
	assert.Equal(t, 1, byVendor["aruba"].CoASuccessCount)
	assert.Less(t, byVendor["aruba"].CompatibilityScore, 100)

	summary, err := GetVendorObservabilitySummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalVendors)
	assert.Equal(t, 2, summary.AuthSuccessCount)
	assert.Equal(t, 1, summary.AuthFailureCount)
	assert.Equal(t, 1, summary.CoAFailureCount)
	assert.Equal(t, "cisco", summary.WorstVendorKey)
}
