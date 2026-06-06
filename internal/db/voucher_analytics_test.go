package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVoucherAnalytics(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "voucher-analytics-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	originalNow := voucherAnalyticsNow
	voucherAnalyticsNow = func() time.Time {
		return time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	}
	defer func() {
		voucherAnalyticsNow = originalNow
	}()

	_, err = DB.Exec(`INSERT INTO vouchers (
		code, role, duration_minutes, usage_limit, used_count, expires_at, created_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?)`,
		"V-001", "guest-basic", 1440, 1, 0, "2026-06-04T12:00:00Z", "2026-06-02T09:00:00Z",
		"V-002", "guest-basic", 720, 5, 2, "2026-06-03T12:00:00Z", "2026-06-02T06:00:00Z",
		"V-003", "guest-vip", 60, 2, 2, "2026-06-03T12:00:00Z", "2026-06-01T15:00:00Z",
		"V-004", "guest-basic", 1440, 1, 0, "2026-06-01T08:00:00Z", "2026-06-01T07:00:00Z",
		"V-005", "guest-standard", 30, 3, 3, "2026-06-02T11:00:00Z", "2026-06-01T23:00:00Z",
	)
	require.NoError(t, err)

	summary, err := GetVoucherAnalytics(VoucherAnalyticsQuery{
		Window:      48 * time.Hour,
		BucketCount: 4,
	})
	require.NoError(t, err)

	assert.Equal(t, 48, summary.WindowHours)
	assert.Equal(t, 4, summary.BucketCount)
	assert.Equal(t, 720, summary.BucketMinutes)
	assert.Equal(t, 5, summary.TotalVouchers)
	assert.Equal(t, 5, summary.CreatedInWindowCount)
	assert.Equal(t, 2, summary.ActiveCount)
	assert.Equal(t, 1, summary.ExhaustedCount)
	assert.Equal(t, 2, summary.ExpiredCount)
	assert.Equal(t, 1, summary.ExpiredUnusedCount)
	assert.Equal(t, 2, summary.UnusedCount)
	assert.Equal(t, 1, summary.PartiallyUsedCount)
	assert.Equal(t, 2, summary.FullyUsedCount)
	assert.Equal(t, 1, summary.Expiring24HoursCount)
	assert.Equal(t, 2, summary.Expiring7DaysCount)
	assert.Equal(t, int64(12), summary.TotalIssuedUses)
	assert.Equal(t, int64(7), summary.TotalUsedUses)
	assert.Equal(t, int64(4), summary.ActiveRemainingUses)
	assert.Equal(t, 58, summary.UtilizationPercent)
	assert.Equal(t, int64(738), summary.AvgDurationMinutes)
	assert.Equal(t, int64(1440), summary.MaxDurationMinutes)
	assert.Equal(t, "2026-06-02T09:00:00Z", summary.LatestCreatedAt)
	require.Len(t, summary.Roles, 3)
	assert.Equal(t, "guest-basic", summary.Roles[0].Name)
	assert.Equal(t, 3, summary.Roles[0].Count)
	require.Len(t, summary.States, 3)
	assert.Equal(t, "active", summary.States[0].Name)
	assert.Equal(t, 2, summary.States[0].Count)
	require.Len(t, summary.Buckets, 4)
	assert.Equal(t, 0, summary.Buckets[0].CreatedCount)
	assert.Equal(t, 1, summary.Buckets[1].CreatedCount)
	assert.Equal(t, 1, summary.Buckets[1].ExpiredCount)
	assert.Equal(t, 1, summary.Buckets[1].UnusedCount)
	assert.Equal(t, 2, summary.Buckets[2].CreatedCount)
	assert.Equal(t, 1, summary.Buckets[2].ExhaustedCount)
	assert.Equal(t, 1, summary.Buckets[2].ExpiredCount)
	assert.Equal(t, 2, summary.Buckets[3].CreatedCount)
	assert.Equal(t, 2, summary.Buckets[3].ActiveCount)
	assert.Equal(t, 1, summary.Buckets[3].UnusedCount)
}
