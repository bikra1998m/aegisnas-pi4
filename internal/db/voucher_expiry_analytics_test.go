package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVoucherExpiryAnalytics(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "voucher-expiry-analytics-*.db")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Remove(tmpfile.Name())
	})
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	t.Cleanup(func() {
		_ = Close()
	})
	require.NoError(t, Migrate())

	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	origNow := voucherExpiryAnalyticsNow
	voucherExpiryAnalyticsNow = func() time.Time { return now }
	t.Cleanup(func() {
		voucherExpiryAnalyticsNow = origNow
	})

	_, err = DB.Exec(`INSERT INTO vouchers (
		code, role, duration_minutes, usage_limit, used_count, expires_at, created_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?)`,
		"VE-001", "guest-basic", 1440, 1, 0, now.Add(6*time.Hour).Format(time.RFC3339), now.Add(-24*time.Hour).Format(time.RFC3339),
		"VE-002", "guest-basic", 720, 5, 2, now.Add(48*time.Hour).Format(time.RFC3339), now.Add(-48*time.Hour).Format(time.RFC3339),
		"VE-003", "guest-vip", 60, 2, 2, now.Add(72*time.Hour).Format(time.RFC3339), now.Add(-72*time.Hour).Format(time.RFC3339),
		"VE-004", "guest-basic", 1440, 1, 0, now.Add(-6*time.Hour).Format(time.RFC3339), now.Add(-96*time.Hour).Format(time.RFC3339),
		"VE-005", "guest-standard", 30, 3, 1, "", now.Add(-3*time.Hour).Format(time.RFC3339),
		"VE-006", "guest-basic", 1440, 3, 1, now.Add(20*24*time.Hour).Format(time.RFC3339), now.Add(-12*time.Hour).Format(time.RFC3339),
	)
	require.NoError(t, err)

	summary, err := GetVoucherExpiryAnalytics(VoucherExpiryQuery{
		Window:      7 * 24 * time.Hour,
		BucketCount: 7,
	})
	require.NoError(t, err)

	assert.Equal(t, 6, summary.TotalVouchers)
	assert.Equal(t, 3, summary.ActiveWithExpiryCount)
	assert.Equal(t, 1, summary.NoExpiryCount)
	assert.Equal(t, 1, summary.ExpiredCount)
	assert.Equal(t, 1, summary.ExpiredUnusedCount)
	assert.Equal(t, 1, summary.Expiring24HoursCount)
	assert.Equal(t, 3, summary.Expiring7DaysCount)
	assert.Equal(t, 3, summary.ExpiringInWindowCount)
	assert.Equal(t, 1, summary.UnusedExpiringInWindowCount)
	assert.Equal(t, 2, summary.ActiveExpiringInWindowCount)
	assert.Equal(t, 1, summary.ExhaustedExpiringInWindowCount)
	assert.EqualValues(t, 4, summary.TotalRemainingUsesExpiringInWindow)
	assert.Equal(t, now.Add(6*time.Hour).Format(time.RFC3339), summary.SoonestExpiryAt)
	assert.Equal(t, now.Add(72*time.Hour).Format(time.RFC3339), summary.LatestExpiryInWindowAt)
	require.Len(t, summary.Roles, 2)
	assert.Equal(t, "guest-basic", summary.Roles[0].Name)
	assert.Equal(t, 2, summary.Roles[0].Count)
	require.Len(t, summary.UnusedRoles, 1)
	assert.Equal(t, "guest-basic", summary.UnusedRoles[0].Name)
	assert.Equal(t, 1, summary.UnusedRoles[0].Count)
	require.NotEmpty(t, summary.Buckets)
	assert.Equal(t, 1, summary.Buckets[0].ExpiringCount)
}
