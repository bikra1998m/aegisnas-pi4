package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVoucherRedemptionAnalytics(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "voucher-redemption-analytics-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	originalNow := voucherRedemptionAnalyticsNow
	voucherRedemptionAnalyticsNow = func() time.Time {
		return time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	}
	defer func() {
		voucherRedemptionAnalyticsNow = originalNow
	}()

	_, err = DB.Exec(`INSERT INTO vouchers (
		code, role, duration_minutes, usage_limit, used_count, expires_at, created_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?)`,
		"V-001", "guest-basic", 1440, 1, 1, "2026-06-04T12:00:00Z", "2026-06-01T10:00:00Z",
		"V-002", "guest-basic", 720, 5, 2, "2026-06-03T12:00:00Z", "2026-06-01T09:00:00Z",
		"V-003", "guest-vip", 60, 2, 2, "2026-06-03T12:00:00Z", "2026-06-01T11:30:00Z",
		"V-004", "guest-basic", 1440, 1, 0, "2026-06-01T08:00:00Z", "2026-06-01T07:00:00Z",
		"V-005", "guest-standard", 30, 3, 0, "2026-06-05T12:00:00Z", "2026-06-02T09:00:00Z",
	)
	require.NoError(t, err)

	_, err = DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, role, start_time, last_activity, end_time, bytes_in, bytes_out, acct_session_time
	) VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"s1", "voucher_V-001", "aa:bb:cc:00:00:01", "192.168.50.10", "voucher", "guest-basic", "2026-06-01T12:00:00Z", "2026-06-01T12:25:00Z", "2026-06-01T12:30:00Z", 100, 200, 1800,
		"s2", "voucher_V-002", "aa:bb:cc:00:00:02", "192.168.50.11", "voucher", "guest-basic", "2026-06-01T10:00:00Z", "2026-06-01T10:10:00Z", "2026-06-01T10:20:00Z", 50, 75, 1200,
		"s3", "voucher_V-002", "aa:bb:cc:00:00:03", "192.168.50.12", "voucher", "guest-basic", "2026-06-02T10:00:00Z", "2026-06-02T10:20:00Z", "", 0, 0, 0,
		"s4", "voucher_V-003", "aa:bb:cc:00:00:04", "192.168.50.13", "voucher", "guest-vip", "2026-06-01T16:00:00Z", "2026-06-01T16:03:00Z", "2026-06-01T16:05:00Z", 500, 700, 300,
	)
	require.NoError(t, err)

	summary, err := GetVoucherRedemptionAnalytics(VoucherRedemptionQuery{
		Window:      48 * time.Hour,
		BucketCount: 4,
	})
	require.NoError(t, err)

	assert.Equal(t, 48, summary.WindowHours)
	assert.Equal(t, 4, summary.BucketCount)
	assert.Equal(t, 720, summary.BucketMinutes)
	assert.Equal(t, 5, summary.TotalVouchers)
	assert.Equal(t, 3, summary.RedeemedVoucherCount)
	assert.Equal(t, 2, summary.NeverRedeemedCount)
	assert.Equal(t, 3, summary.RedeemedInWindowCount)
	assert.Equal(t, 3, summary.FirstRedeemedInWindowCount)
	assert.Equal(t, 2, summary.RedeemedOnceCount)
	assert.Equal(t, 1, summary.RedeemedRepeatCount)
	assert.Equal(t, 4, summary.SessionStartCount)
	assert.Equal(t, 3, summary.EndedSessionCount)
	assert.Equal(t, 1, summary.ActiveSessionCount)
	assert.Equal(t, 1, summary.ActiveVoucherCount)
	assert.Equal(t, 3, summary.RedeemedWithin24HoursCount)
	assert.Equal(t, 3, summary.RedeemedWithin7DaysCount)
	assert.InDelta(t, 1.33, summary.AvgSessionsPerRedeemedVoucher, 0.01)
	assert.Equal(t, int64(150), summary.AvgFirstRedemptionDelayMinutes)
	assert.Equal(t, int64(270), summary.MaxFirstRedemptionDelayMinutes)
	assert.Equal(t, int64(1625), summary.EndedTrafficTotal)
	assert.Equal(t, int64(1100), summary.AvgEndedSessionSeconds)
	assert.Equal(t, int64(1800), summary.MaxEndedSessionSeconds)
	assert.Equal(t, "2026-06-02T10:00:00Z", summary.LatestSessionStartAt)
	require.Len(t, summary.Roles, 2)
	assert.Equal(t, "guest-basic", summary.Roles[0].Name)
	assert.Equal(t, 2, summary.Roles[0].Count)
	require.Len(t, summary.Buckets, 4)
	assert.Equal(t, 1, summary.Buckets[1].SessionStartCount)
	assert.Equal(t, 1, summary.Buckets[1].UniqueVoucherCount)
	assert.Equal(t, 1, summary.Buckets[1].FirstRedeemedCount)
	assert.Equal(t, 1, summary.Buckets[1].EndedCount)
	assert.Equal(t, int64(125), summary.Buckets[1].EndedTrafficTotal)
	assert.Equal(t, 2, summary.Buckets[2].SessionStartCount)
	assert.Equal(t, 2, summary.Buckets[2].UniqueVoucherCount)
	assert.Equal(t, 2, summary.Buckets[2].FirstRedeemedCount)
	assert.Equal(t, 2, summary.Buckets[2].EndedCount)
	assert.Equal(t, int64(1500), summary.Buckets[2].EndedTrafficTotal)
	assert.Equal(t, 1, summary.Buckets[3].SessionStartCount)
	assert.Equal(t, 1, summary.Buckets[3].UniqueVoucherCount)
	assert.Equal(t, 0, summary.Buckets[3].FirstRedeemedCount)
	assert.Equal(t, 0, summary.Buckets[3].EndedCount)
}
