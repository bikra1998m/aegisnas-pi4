package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVoucherAgingAnalytics(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "voucher-aging-analytics-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	originalNow := voucherAgingAnalyticsNow
	voucherAgingAnalyticsNow = func() time.Time {
		return time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	}
	defer func() {
		voucherAgingAnalyticsNow = originalNow
	}()

	_, err = DB.Exec(`INSERT INTO vouchers (
		code, role, duration_minutes, usage_limit, used_count, expires_at, created_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?)`,
		"VA-001", "guest-basic", 1440, 1, 0, "2026-06-04T12:00:00Z", "2026-06-02T09:00:00Z",
		"VA-002", "guest-basic", 720, 5, 2, "2026-06-03T12:00:00Z", "2026-05-31T12:00:00Z",
		"VA-003", "guest-vip", 60, 2, 2, "2026-05-30T12:00:00Z", "2026-05-20T12:00:00Z",
		"VA-004", "guest-basic", 1440, 1, 0, "2026-06-10T12:00:00Z", "2026-05-25T12:00:00Z",
		"VA-005", "guest-standard", 30, 3, 0, "", "2026-05-01T12:00:00Z",
		"VA-006", "guest-basic", 1440, 3, 1, "2026-06-20T12:00:00Z", "2026-05-30T12:00:00Z",
	)
	require.NoError(t, err)

	summary, err := GetVoucherAgingAnalytics(VoucherAgingQuery{
		Window:      7 * 24 * time.Hour,
		BucketCount: 7,
	})
	require.NoError(t, err)

	assert.Equal(t, 168, summary.WindowHours)
	assert.Equal(t, 7, summary.BucketCount)
	assert.Equal(t, 1440, summary.BucketMinutes)
	assert.Equal(t, 6, summary.TotalVouchers)
	assert.Equal(t, 3, summary.WithinWindowCount)
	assert.Equal(t, 3, summary.OlderThanWindowCount)
	assert.Equal(t, 1, summary.UnusedWithinWindowCount)
	assert.Equal(t, 2, summary.UnusedOlderThanWindowCount)
	assert.Equal(t, 2, summary.ActiveOlderThanWindowCount)
	assert.Equal(t, 0, summary.ExhaustedOlderThanWindowCount)
	assert.Equal(t, 1, summary.ExpiredOlderThanWindowCount)
	assert.Equal(t, int64(4), summary.RemainingUsesOlderThanWindow)
	assert.Equal(t, 2, summary.UnusedOlder24HoursCount)
	assert.Equal(t, 2, summary.UnusedOlder7DaysCount)
	assert.Equal(t, 1, summary.UnusedOlder30DaysCount)
	assert.Equal(t, int64(13950), summary.AvgAgeMinutes)
	assert.Equal(t, int64(46080), summary.MaxAgeMinutes)
	assert.Equal(t, int64(19260), summary.AvgUnusedAgeMinutes)
	assert.Equal(t, int64(46080), summary.MaxUnusedAgeMinutes)
	assert.Equal(t, "2026-06-02T09:00:00Z", summary.NewestCreatedAt)
	assert.Equal(t, "2026-05-01T12:00:00Z", summary.OldestCreatedAt)
	assert.Equal(t, "2026-05-01T12:00:00Z", summary.OldestUnusedCreatedAt)
	require.Len(t, summary.OlderRoles, 3)
	assert.Equal(t, "guest-basic", summary.OlderRoles[0].Name)
	assert.Equal(t, 1, summary.OlderRoles[0].Count)
	assert.Equal(t, "guest-standard", summary.OlderRoles[1].Name)
	assert.Equal(t, 1, summary.OlderRoles[1].Count)
	assert.Equal(t, "guest-vip", summary.OlderRoles[2].Name)
	assert.Equal(t, 1, summary.OlderRoles[2].Count)
	require.Len(t, summary.UnusedOlderRoles, 2)
	assert.Equal(t, "guest-basic", summary.UnusedOlderRoles[0].Name)
	assert.Equal(t, 1, summary.UnusedOlderRoles[0].Count)
	assert.Equal(t, "guest-standard", summary.UnusedOlderRoles[1].Name)
	assert.Equal(t, 1, summary.UnusedOlderRoles[1].Count)
	require.Len(t, summary.Buckets, 7)
	assert.Equal(t, 1, summary.Buckets[0].VoucherCount)
	assert.Equal(t, 1, summary.Buckets[0].UnusedCount)
	assert.Equal(t, 1, summary.Buckets[0].ActiveCount)
	assert.Equal(t, int64(1), summary.Buckets[0].RemainingUses)
	assert.Equal(t, 0, summary.Buckets[1].VoucherCount)
	assert.Equal(t, 1, summary.Buckets[2].VoucherCount)
	assert.Equal(t, int64(3), summary.Buckets[2].RemainingUses)
	assert.Equal(t, 1, summary.Buckets[3].VoucherCount)
	assert.Equal(t, 0, summary.Buckets[3].UnusedCount)
	assert.Equal(t, 1, summary.Buckets[3].ActiveCount)
	assert.Equal(t, int64(2), summary.Buckets[3].RemainingUses)
}
