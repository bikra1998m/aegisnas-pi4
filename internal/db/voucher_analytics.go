package db

import (
	"fmt"
	"time"
)

const (
	defaultVoucherAnalyticsWindow      = 30 * 24 * time.Hour
	defaultVoucherAnalyticsBucketCount = 30
	maxVoucherAnalyticsBucketCount     = 90
)

var voucherAnalyticsNow = time.Now

type VoucherAnalyticsQuery struct {
	Window      time.Duration
	BucketCount int
}

type VoucherAnalyticsSummary struct {
	WindowHours          int                      `json:"window_hours"`
	BucketCount          int                      `json:"bucket_count"`
	BucketMinutes        int                      `json:"bucket_minutes"`
	TotalVouchers        int                      `json:"total_vouchers"`
	CreatedInWindowCount int                      `json:"created_in_window_count"`
	ActiveCount          int                      `json:"active_count"`
	ExhaustedCount       int                      `json:"exhausted_count"`
	ExpiredCount         int                      `json:"expired_count"`
	ExpiredUnusedCount   int                      `json:"expired_unused_count"`
	UnusedCount          int                      `json:"unused_count"`
	PartiallyUsedCount   int                      `json:"partially_used_count"`
	FullyUsedCount       int                      `json:"fully_used_count"`
	Expiring24HoursCount int                      `json:"expiring_24_hours_count"`
	Expiring7DaysCount   int                      `json:"expiring_7_days_count"`
	TotalIssuedUses      int64                    `json:"total_issued_uses"`
	TotalUsedUses        int64                    `json:"total_used_uses"`
	ActiveRemainingUses  int64                    `json:"active_remaining_uses"`
	UtilizationPercent   int                      `json:"utilization_percent"`
	AvgDurationMinutes   int64                    `json:"avg_duration_minutes"`
	MaxDurationMinutes   int64                    `json:"max_duration_minutes"`
	LatestCreatedAt      string                   `json:"latest_created_at"`
	Roles                []SessionAnalyticsCount  `json:"roles"`
	States               []SessionAnalyticsCount  `json:"states"`
	Buckets              []VoucherAnalyticsBucket `json:"buckets"`
}

type VoucherAnalyticsBucket struct {
	Start          string `json:"start"`
	End            string `json:"end"`
	CreatedCount   int    `json:"created_count"`
	ActiveCount    int    `json:"active_count"`
	ExhaustedCount int    `json:"exhausted_count"`
	ExpiredCount   int    `json:"expired_count"`
	UnusedCount    int    `json:"unused_count"`
}

func GetVoucherAnalytics(query VoucherAnalyticsQuery) (VoucherAnalyticsSummary, error) {
	if DB == nil {
		return VoucherAnalyticsSummary{}, fmt.Errorf("database not initialized")
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

	now := voucherAnalyticsNow().UTC()
	cutoff := now.Add(-window)
	bucketDuration := window / time.Duration(bucketCount)
	if bucketDuration <= 0 {
		bucketDuration = 24 * time.Hour
	}

	rows, err := DB.Query(`SELECT role, duration_minutes, usage_limit, used_count, COALESCE(expires_at, ''), created_at FROM vouchers ORDER BY created_at DESC`)
	if err != nil {
		return VoucherAnalyticsSummary{}, err
	}
	defer rows.Close()

	buckets := make([]VoucherAnalyticsBucket, bucketCount)
	for i := range buckets {
		start := cutoff.Add(time.Duration(i) * bucketDuration)
		end := start.Add(bucketDuration)
		if i == bucketCount-1 {
			end = now
		}
		buckets[i] = VoucherAnalyticsBucket{
			Start: start.Format(time.RFC3339),
			End:   end.Format(time.RFC3339),
		}
	}

	summary := VoucherAnalyticsSummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketDuration.Minutes()),
		Buckets:       buckets,
	}

	roleCounts := map[string]int{}
	stateCounts := map[string]int{}
	var durationTotal int64

	for rows.Next() {
		var (
			role            string
			durationMinutes int
			usageLimit      int
			usedCount       int
			expiresAtRaw    string
			createdAtRaw    string
		)
		if err := rows.Scan(&role, &durationMinutes, &usageLimit, &usedCount, &expiresAtRaw, &createdAtRaw); err != nil {
			return VoucherAnalyticsSummary{}, err
		}

		createdAt := parseSessionAnalyticsTime(createdAtRaw)
		expiresAt := parseSessionAnalyticsTime(expiresAtRaw)
		expired := !expiresAt.IsZero() && expiresAt.Before(now)
		exhausted := usageLimit > 0 && usedCount >= usageLimit
		active := !expired && !exhausted

		summary.TotalVouchers++
		durationTotal += int64(durationMinutes)
		if int64(durationMinutes) > summary.MaxDurationMinutes {
			summary.MaxDurationMinutes = int64(durationMinutes)
		}
		if createdAtText := voucherAnalyticsTimeText(createdAt); createdAtText != "" && createdAtText > summary.LatestCreatedAt {
			summary.LatestCreatedAt = createdAtText
		}

		if usageLimit > 0 {
			summary.TotalIssuedUses += int64(usageLimit)
			if usedCount > usageLimit {
				usedCount = usageLimit
			}
		}
		if usedCount > 0 {
			summary.TotalUsedUses += int64(usedCount)
		}

		if active && usageLimit > usedCount {
			summary.ActiveRemainingUses += int64(usageLimit - usedCount)
		}
		if usedCount == 0 {
			summary.UnusedCount++
		}
		if usageLimit > 0 && usedCount > 0 && usedCount < usageLimit {
			summary.PartiallyUsedCount++
		}
		if usageLimit > 0 && usedCount >= usageLimit {
			summary.FullyUsedCount++
		}

		stateName := "active"
		switch {
		case expired:
			summary.ExpiredCount++
			stateName = "expired"
			if usedCount == 0 {
				summary.ExpiredUnusedCount++
			}
		case exhausted:
			summary.ExhaustedCount++
			stateName = "exhausted"
		default:
			summary.ActiveCount++
			if !expiresAt.IsZero() && !expiresAt.Before(now) {
				if !expiresAt.After(now.Add(24 * time.Hour)) {
					summary.Expiring24HoursCount++
				}
				if !expiresAt.After(now.Add(7 * 24 * time.Hour)) {
					summary.Expiring7DaysCount++
				}
			}
		}

		if role == "" {
			role = "unassigned"
		}
		roleCounts[role]++
		stateCounts[stateName]++

		if !createdAt.IsZero() && !createdAt.Before(cutoff) {
			summary.CreatedInWindowCount++
			idx := bucketIndex(createdAt, cutoff, bucketDuration, bucketCount)
			buckets[idx].CreatedCount++
			switch stateName {
			case "active":
				buckets[idx].ActiveCount++
			case "exhausted":
				buckets[idx].ExhaustedCount++
			case "expired":
				buckets[idx].ExpiredCount++
			}
			if usedCount == 0 {
				buckets[idx].UnusedCount++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return VoucherAnalyticsSummary{}, err
	}

	if summary.TotalVouchers > 0 {
		summary.AvgDurationMinutes = durationTotal / int64(summary.TotalVouchers)
	}
	if summary.TotalIssuedUses > 0 {
		summary.UtilizationPercent = int((summary.TotalUsedUses * 100) / summary.TotalIssuedUses)
	}
	summary.Roles = sessionAnalyticsCounts(roleCounts)
	summary.States = sessionAnalyticsCounts(stateCounts)
	summary.Buckets = buckets

	return summary, nil
}

func voucherAnalyticsTimeText(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
