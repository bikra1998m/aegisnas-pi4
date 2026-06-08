package db

import (
	"fmt"
	"strings"
	"time"
)

var voucherAgingAnalyticsNow = time.Now

type VoucherAgingQuery struct {
	Window      time.Duration
	BucketCount int
}

type VoucherAgingBucket struct {
	MinAgeMinutes  int   `json:"min_age_minutes"`
	MaxAgeMinutes  int   `json:"max_age_minutes"`
	VoucherCount   int   `json:"voucher_count"`
	UnusedCount    int   `json:"unused_count"`
	ActiveCount    int   `json:"active_count"`
	ExhaustedCount int   `json:"exhausted_count"`
	ExpiredCount   int   `json:"expired_count"`
	RemainingUses  int64 `json:"remaining_uses"`
}

type VoucherAgingSummary struct {
	WindowHours                   int                     `json:"window_hours"`
	BucketCount                   int                     `json:"bucket_count"`
	BucketMinutes                 int                     `json:"bucket_minutes"`
	TotalVouchers                 int                     `json:"total_vouchers"`
	WithinWindowCount             int                     `json:"within_window_count"`
	OlderThanWindowCount          int                     `json:"older_than_window_count"`
	UnusedWithinWindowCount       int                     `json:"unused_within_window_count"`
	UnusedOlderThanWindowCount    int                     `json:"unused_older_than_window_count"`
	ActiveOlderThanWindowCount    int                     `json:"active_older_than_window_count"`
	ExhaustedOlderThanWindowCount int                     `json:"exhausted_older_than_window_count"`
	ExpiredOlderThanWindowCount   int                     `json:"expired_older_than_window_count"`
	RemainingUsesOlderThanWindow  int64                   `json:"remaining_uses_older_than_window"`
	UnusedOlder24HoursCount       int                     `json:"unused_older_24_hours_count"`
	UnusedOlder7DaysCount         int                     `json:"unused_older_7_days_count"`
	UnusedOlder30DaysCount        int                     `json:"unused_older_30_days_count"`
	AvgAgeMinutes                 int64                   `json:"avg_age_minutes"`
	MaxAgeMinutes                 int64                   `json:"max_age_minutes"`
	AvgUnusedAgeMinutes           int64                   `json:"avg_unused_age_minutes"`
	MaxUnusedAgeMinutes           int64                   `json:"max_unused_age_minutes"`
	NewestCreatedAt               string                  `json:"newest_created_at"`
	OldestCreatedAt               string                  `json:"oldest_created_at"`
	OldestUnusedCreatedAt         string                  `json:"oldest_unused_created_at"`
	OlderRoles                    []SessionAnalyticsCount `json:"older_roles"`
	UnusedOlderRoles              []SessionAnalyticsCount `json:"unused_older_roles"`
	Buckets                       []VoucherAgingBucket    `json:"buckets"`
}

func GetVoucherAgingAnalytics(query VoucherAgingQuery) (VoucherAgingSummary, error) {
	if DB == nil {
		return VoucherAgingSummary{}, fmt.Errorf("database not initialized")
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

	now := voucherAgingAnalyticsNow().UTC()
	windowMinutes := int64(window / time.Minute)
	if windowMinutes <= 0 {
		windowMinutes = 1
	}
	bucketDuration := window / time.Duration(bucketCount)
	if bucketDuration <= 0 {
		bucketDuration = time.Hour
	}
	bucketMinutes := int64(bucketDuration / time.Minute)
	if bucketMinutes <= 0 {
		bucketMinutes = 1
	}

	rows, err := DB.Query(`SELECT COALESCE(role, ''), usage_limit, used_count, COALESCE(expires_at, ''), COALESCE(created_at, '') FROM vouchers ORDER BY datetime(created_at) ASC, code ASC`)
	if err != nil {
		return VoucherAgingSummary{}, err
	}
	defer rows.Close()

	buckets := make([]VoucherAgingBucket, bucketCount)
	for i := range buckets {
		minAgeMinutes := int(bucketMinutes * int64(i))
		maxAgeMinutes := int(bucketMinutes * int64(i+1))
		if i == bucketCount-1 {
			maxAgeMinutes = int(windowMinutes)
		}
		buckets[i] = VoucherAgingBucket{
			MinAgeMinutes: minAgeMinutes,
			MaxAgeMinutes: maxAgeMinutes,
		}
	}

	summary := VoucherAgingSummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketMinutes),
		Buckets:       buckets,
	}

	olderRoleCounts := map[string]int{}
	unusedOlderRoleCounts := map[string]int{}
	var (
		ageTotalMinutes       int64
		ageCount              int64
		unusedAgeTotalMinutes int64
		unusedAgeCount        int64
		newestCreated         time.Time
		oldestCreated         time.Time
		oldestUnusedCreated   time.Time
	)

	for rows.Next() {
		var (
			role         string
			usageLimit   int
			usedCount    int
			expiresAtRaw string
			createdAtRaw string
		)
		if err := rows.Scan(&role, &usageLimit, &usedCount, &expiresAtRaw, &createdAtRaw); err != nil {
			return VoucherAgingSummary{}, err
		}

		summary.TotalVouchers++
		role = strings.TrimSpace(role)
		if role == "" {
			role = "unassigned"
		}
		if usageLimit > 0 && usedCount > usageLimit {
			usedCount = usageLimit
		}

		createdAt := parseSessionAnalyticsTime(createdAtRaw)
		if createdAt.IsZero() {
			continue
		}
		if newestCreated.IsZero() || createdAt.After(newestCreated) {
			newestCreated = createdAt
		}
		if oldestCreated.IsZero() || createdAt.Before(oldestCreated) {
			oldestCreated = createdAt
		}

		expiresAt := parseSessionAnalyticsTime(expiresAtRaw)
		expired := !expiresAt.IsZero() && expiresAt.Before(now)
		exhausted := usageLimit > 0 && usedCount >= usageLimit
		active := !expired && !exhausted
		unused := usedCount == 0

		ageMinutes := int64(now.Sub(createdAt).Minutes())
		if ageMinutes < 0 {
			ageMinutes = 0
		}
		ageTotalMinutes += ageMinutes
		ageCount++
		if ageMinutes > summary.MaxAgeMinutes {
			summary.MaxAgeMinutes = ageMinutes
		}

		if unused {
			unusedAgeTotalMinutes += ageMinutes
			unusedAgeCount++
			if ageMinutes > summary.MaxUnusedAgeMinutes {
				summary.MaxUnusedAgeMinutes = ageMinutes
			}
			if oldestUnusedCreated.IsZero() || createdAt.Before(oldestUnusedCreated) {
				oldestUnusedCreated = createdAt
			}
			if ageMinutes >= int64((24*time.Hour)/time.Minute) {
				summary.UnusedOlder24HoursCount++
			}
			if ageMinutes >= int64((7*24*time.Hour)/time.Minute) {
				summary.UnusedOlder7DaysCount++
			}
			if ageMinutes >= int64((30*24*time.Hour)/time.Minute) {
				summary.UnusedOlder30DaysCount++
			}
		}

		remainingUses := int64(0)
		if usageLimit > 0 && usedCount < usageLimit {
			remainingUses = int64(usageLimit - usedCount)
		}

		if ageMinutes > windowMinutes {
			summary.OlderThanWindowCount++
			olderRoleCounts[role]++
			summary.RemainingUsesOlderThanWindow += remainingUses
			switch {
			case active:
				summary.ActiveOlderThanWindowCount++
			case expired:
				summary.ExpiredOlderThanWindowCount++
			case exhausted:
				summary.ExhaustedOlderThanWindowCount++
			}
			if unused {
				summary.UnusedOlderThanWindowCount++
				unusedOlderRoleCounts[role]++
			}
			continue
		}

		summary.WithinWindowCount++
		if unused {
			summary.UnusedWithinWindowCount++
		}

		index := int(ageMinutes / bucketMinutes)
		if index >= bucketCount {
			index = bucketCount - 1
		}
		buckets[index].VoucherCount++
		buckets[index].RemainingUses += remainingUses
		if unused {
			buckets[index].UnusedCount++
		}
		switch {
		case active:
			buckets[index].ActiveCount++
		case expired:
			buckets[index].ExpiredCount++
		case exhausted:
			buckets[index].ExhaustedCount++
		}
	}
	if err := rows.Err(); err != nil {
		return VoucherAgingSummary{}, err
	}

	if ageCount > 0 {
		summary.AvgAgeMinutes = ageTotalMinutes / ageCount
	}
	if unusedAgeCount > 0 {
		summary.AvgUnusedAgeMinutes = unusedAgeTotalMinutes / unusedAgeCount
	}
	if !newestCreated.IsZero() {
		summary.NewestCreatedAt = newestCreated.Format(time.RFC3339)
	}
	if !oldestCreated.IsZero() {
		summary.OldestCreatedAt = oldestCreated.Format(time.RFC3339)
	}
	if !oldestUnusedCreated.IsZero() {
		summary.OldestUnusedCreatedAt = oldestUnusedCreated.Format(time.RFC3339)
	}
	summary.OlderRoles = sessionAnalyticsCounts(olderRoleCounts)
	summary.UnusedOlderRoles = sessionAnalyticsCounts(unusedOlderRoleCounts)
	summary.Buckets = buckets

	return summary, nil
}
