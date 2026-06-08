package db

import (
	"fmt"
	"strings"
	"time"
)

var voucherExpiryAnalyticsNow = time.Now

type VoucherExpiryQuery struct {
	Window      time.Duration
	BucketCount int
}

type VoucherExpiryBucket struct {
	Start                  string `json:"start"`
	End                    string `json:"end"`
	ExpiringCount          int    `json:"expiring_count"`
	UnusedExpiringCount    int    `json:"unused_expiring_count"`
	ActiveExpiringCount    int    `json:"active_expiring_count"`
	ExhaustedExpiringCount int    `json:"exhausted_expiring_count"`
	RemainingUses          int64  `json:"remaining_uses"`
}

type VoucherExpirySummary struct {
	WindowHours                        int                     `json:"window_hours"`
	BucketCount                        int                     `json:"bucket_count"`
	BucketMinutes                      int                     `json:"bucket_minutes"`
	TotalVouchers                      int                     `json:"total_vouchers"`
	ActiveWithExpiryCount              int                     `json:"active_with_expiry_count"`
	NoExpiryCount                      int                     `json:"no_expiry_count"`
	ExpiredCount                       int                     `json:"expired_count"`
	ExpiredUnusedCount                 int                     `json:"expired_unused_count"`
	ExpiredUsedCount                   int                     `json:"expired_used_count"`
	Expiring24HoursCount               int                     `json:"expiring_24_hours_count"`
	Expiring7DaysCount                 int                     `json:"expiring_7_days_count"`
	ExpiringInWindowCount              int                     `json:"expiring_in_window_count"`
	UnusedExpiringInWindowCount        int                     `json:"unused_expiring_in_window_count"`
	ActiveExpiringInWindowCount        int                     `json:"active_expiring_in_window_count"`
	ExhaustedExpiringInWindowCount     int                     `json:"exhausted_expiring_in_window_count"`
	TotalRemainingUsesExpiringInWindow int64                   `json:"total_remaining_uses_expiring_in_window"`
	AvgHoursUntilExpiry                int64                   `json:"avg_hours_until_expiry"`
	MaxHoursUntilExpiry                int64                   `json:"max_hours_until_expiry"`
	AvgExpiredHoursAgo                 int64                   `json:"avg_expired_hours_ago"`
	MaxExpiredHoursAgo                 int64                   `json:"max_expired_hours_ago"`
	SoonestExpiryAt                    string                  `json:"soonest_expiry_at"`
	LatestExpiryInWindowAt             string                  `json:"latest_expiry_in_window_at"`
	Roles                              []SessionAnalyticsCount `json:"roles"`
	UnusedRoles                        []SessionAnalyticsCount `json:"unused_roles"`
	States                             []SessionAnalyticsCount `json:"states"`
	Buckets                            []VoucherExpiryBucket   `json:"buckets"`
}

func GetVoucherExpiryAnalytics(query VoucherExpiryQuery) (VoucherExpirySummary, error) {
	if DB == nil {
		return VoucherExpirySummary{}, fmt.Errorf("database not initialized")
	}

	window := query.Window
	if window <= 0 {
		window = defaultVoucherAnalyticsWindow
	}
	bucketCount := query.BucketCount
	if bucketCount <= 0 {
		bucketCount = defaultVoucherAnalyticsBucketCount
	}
	if bucketCount > maxVoucherAnalyticsBucketCount {
		bucketCount = maxVoucherAnalyticsBucketCount
	}

	now := voucherExpiryAnalyticsNow().UTC()
	horizonEnd := now.Add(window)
	bucketDuration := window / time.Duration(bucketCount)
	if bucketDuration <= 0 {
		bucketDuration = 24 * time.Hour
	}

	rows, err := DB.Query(`SELECT COALESCE(role, ''), usage_limit, used_count, COALESCE(expires_at, '') FROM vouchers ORDER BY datetime(expires_at) ASC, datetime(created_at) DESC`)
	if err != nil {
		return VoucherExpirySummary{}, err
	}
	defer rows.Close()

	buckets := make([]VoucherExpiryBucket, bucketCount)
	for i := range buckets {
		start := now.Add(time.Duration(i) * bucketDuration)
		end := start.Add(bucketDuration)
		if i == bucketCount-1 {
			end = horizonEnd
		}
		buckets[i] = VoucherExpiryBucket{
			Start: start.Format(time.RFC3339),
			End:   end.Format(time.RFC3339),
		}
	}

	summary := VoucherExpirySummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketDuration.Minutes()),
		Buckets:       buckets,
	}

	roleCounts := map[string]int{}
	unusedRoleCounts := map[string]int{}
	stateCounts := map[string]int{}
	var (
		hoursUntilTotal int64
		hoursUntilCount int64
		hoursAgoTotal   int64
		hoursAgoCount   int64
		soonestExpiry   time.Time
		latestExpiry    time.Time
	)

	for rows.Next() {
		var (
			role         string
			usageLimit   int
			usedCount    int
			expiresAtRaw string
		)
		if err := rows.Scan(&role, &usageLimit, &usedCount, &expiresAtRaw); err != nil {
			return VoucherExpirySummary{}, err
		}

		summary.TotalVouchers++
		role = strings.TrimSpace(role)
		if role == "" {
			role = "unassigned"
		}
		if usageLimit > 0 && usedCount > usageLimit {
			usedCount = usageLimit
		}

		expiresAt := parseSessionAnalyticsTime(expiresAtRaw)
		if expiresAt.IsZero() {
			summary.NoExpiryCount++
			continue
		}

		expired := expiresAt.Before(now)
		exhausted := usageLimit > 0 && usedCount >= usageLimit
		if expired {
			summary.ExpiredCount++
			expiredHoursAgo := int64(now.Sub(expiresAt).Hours())
			hoursAgoTotal += expiredHoursAgo
			hoursAgoCount++
			if expiredHoursAgo > summary.MaxExpiredHoursAgo {
				summary.MaxExpiredHoursAgo = expiredHoursAgo
			}
			if usedCount == 0 {
				summary.ExpiredUnusedCount++
			} else {
				summary.ExpiredUsedCount++
			}
			continue
		}

		if !exhausted {
			summary.ActiveWithExpiryCount++
		}
		if !expiresAt.After(now.Add(24 * time.Hour)) {
			summary.Expiring24HoursCount++
		}
		if !expiresAt.After(now.Add(7 * 24 * time.Hour)) {
			summary.Expiring7DaysCount++
		}
		if expiresAt.After(horizonEnd) {
			continue
		}

		summary.ExpiringInWindowCount++
		roleCounts[role]++

		stateName := "active"
		if exhausted {
			stateName = "exhausted"
			summary.ExhaustedExpiringInWindowCount++
		} else {
			summary.ActiveExpiringInWindowCount++
		}
		stateCounts[stateName]++

		remainingUses := int64(0)
		if usageLimit > 0 && usedCount < usageLimit {
			remainingUses = int64(usageLimit - usedCount)
			summary.TotalRemainingUsesExpiringInWindow += remainingUses
		}
		if usedCount == 0 {
			summary.UnusedExpiringInWindowCount++
			unusedRoleCounts[role]++
		}

		hoursUntilExpiry := int64(expiresAt.Sub(now).Hours())
		hoursUntilTotal += hoursUntilExpiry
		hoursUntilCount++
		if hoursUntilExpiry > summary.MaxHoursUntilExpiry {
			summary.MaxHoursUntilExpiry = hoursUntilExpiry
		}
		if soonestExpiry.IsZero() || expiresAt.Before(soonestExpiry) {
			soonestExpiry = expiresAt
		}
		if latestExpiry.IsZero() || expiresAt.After(latestExpiry) {
			latestExpiry = expiresAt
		}

		index := bucketIndex(expiresAt, now, bucketDuration, bucketCount)
		buckets[index].ExpiringCount++
		buckets[index].RemainingUses += remainingUses
		if usedCount == 0 {
			buckets[index].UnusedExpiringCount++
		}
		if exhausted {
			buckets[index].ExhaustedExpiringCount++
		} else {
			buckets[index].ActiveExpiringCount++
		}
	}
	if err := rows.Err(); err != nil {
		return VoucherExpirySummary{}, err
	}

	if hoursUntilCount > 0 {
		summary.AvgHoursUntilExpiry = hoursUntilTotal / hoursUntilCount
	}
	if hoursAgoCount > 0 {
		summary.AvgExpiredHoursAgo = hoursAgoTotal / hoursAgoCount
	}
	if !soonestExpiry.IsZero() {
		summary.SoonestExpiryAt = soonestExpiry.Format(time.RFC3339)
	}
	if !latestExpiry.IsZero() {
		summary.LatestExpiryInWindowAt = latestExpiry.Format(time.RFC3339)
	}
	summary.Roles = sessionAnalyticsCounts(roleCounts)
	summary.UnusedRoles = sessionAnalyticsCounts(unusedRoleCounts)
	summary.States = sessionAnalyticsCounts(stateCounts)
	summary.Buckets = buckets

	return summary, nil
}
