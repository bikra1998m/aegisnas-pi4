package db

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	guestSponsorPending30Minutes = 30
	guestSponsorPending4Hours    = 4 * 60
	guestSponsorPending24Hours   = 24 * 60
)

type GuestSponsorApprovalSummary struct {
	WindowHours                    int                                `json:"window_hours"`
	BucketCount                    int                                `json:"bucket_count"`
	BucketMinutes                  int                                `json:"bucket_minutes"`
	TotalRecords                   int                                `json:"total_records"`
	SponsorApprovalRequiredCount   int                                `json:"sponsor_approval_required_count"`
	PendingSponsorApprovalCount    int                                `json:"pending_sponsor_approval_count"`
	PendingOlderThan30MinutesCount int                                `json:"pending_older_than_30_minutes_count"`
	PendingOlderThan4HoursCount    int                                `json:"pending_older_than_4_hours_count"`
	PendingOlderThan24HoursCount   int                                `json:"pending_older_than_24_hours_count"`
	ApprovedWithSponsorCount       int                                `json:"approved_with_sponsor_count"`
	RejectedWithSponsorCount       int                                `json:"rejected_with_sponsor_count"`
	CompletedWithSponsorCount      int                                `json:"completed_with_sponsor_count"`
	UniqueSponsorsWindow           int                                `json:"unique_sponsors_window"`
	UniqueCompaniesWindow          int                                `json:"unique_companies_window"`
	AvgApprovalMinutes             int64                              `json:"avg_approval_minutes"`
	MaxApprovalMinutes             int64                              `json:"max_approval_minutes"`
	AvgPendingApprovalMinutes      int64                              `json:"avg_pending_approval_minutes"`
	MaxPendingApprovalMinutes      int64                              `json:"max_pending_approval_minutes"`
	LatestSubmittedAt              string                             `json:"latest_submitted_at"`
	LatestApprovedAt               string                             `json:"latest_approved_at"`
	LatestRejectedAt               string                             `json:"latest_rejected_at"`
	Sponsors                       []GuestSponsorApprovalSponsorStats `json:"sponsors"`
	Companies                      []SessionAnalyticsCount            `json:"companies"`
	Buckets                        []GuestSponsorApprovalBucket       `json:"buckets"`
}

type GuestSponsorApprovalSponsorStats struct {
	Name                    string `json:"name"`
	PendingCount            int    `json:"pending_count"`
	ApprovedCount           int    `json:"approved_count"`
	RejectedCount           int    `json:"rejected_count"`
	CompletedCount          int    `json:"completed_count"`
	OlderThan30MinutesCount int    `json:"older_than_30_minutes_count"`
	OlderThan4HoursCount    int    `json:"older_than_4_hours_count"`
	OlderThan24HoursCount   int    `json:"older_than_24_hours_count"`
	AvgApprovalMinutes      int64  `json:"avg_approval_minutes"`
	MaxApprovalMinutes      int64  `json:"max_approval_minutes"`
	LatestSubmittedAt       string `json:"latest_submitted_at"`
	LatestApprovedAt        string `json:"latest_approved_at"`

	approvalMinutesTotal int64
	approvalSamples      int64
}

type GuestSponsorApprovalBucket struct {
	Start                          string `json:"start"`
	End                            string `json:"end"`
	SubmittedCount                 int    `json:"submitted_count"`
	PendingSponsorApprovalCount    int    `json:"pending_sponsor_approval_count"`
	PendingOlderThan30MinutesCount int    `json:"pending_older_than_30_minutes_count"`
	PendingOlderThan4HoursCount    int    `json:"pending_older_than_4_hours_count"`
	PendingOlderThan24HoursCount   int    `json:"pending_older_than_24_hours_count"`
	ApprovedCount                  int    `json:"approved_count"`
	RejectedCount                  int    `json:"rejected_count"`
	CompletedCount                 int    `json:"completed_count"`
}

func GetGuestSponsorApprovalAnalytics(query GuestLifecycleQuery) (GuestSponsorApprovalSummary, error) {
	if DB == nil {
		return GuestSponsorApprovalSummary{}, fmt.Errorf("database not initialized")
	}

	window := query.Window
	if window <= 0 {
		window = defaultGuestLifecycleWindow
	}
	bucketCount := query.BucketCount
	if bucketCount <= 0 {
		bucketCount = defaultGuestLifecycleBucketCount
	}
	if bucketCount > maxGuestLifecycleBucketCount {
		bucketCount = maxGuestLifecycleBucketCount
	}

	now := guestLifecycleNow().UTC()
	cutoff := now.Add(-window)
	bucketDuration := window / time.Duration(bucketCount)
	if bucketDuration <= 0 {
		bucketDuration = time.Hour
	}

	rows, err := listGuestLifecycleRows(query)
	if err != nil {
		return GuestSponsorApprovalSummary{}, err
	}

	buckets := make([]GuestSponsorApprovalBucket, bucketCount)
	for i := range buckets {
		start := cutoff.Add(time.Duration(i) * bucketDuration)
		end := start.Add(bucketDuration)
		if i == bucketCount-1 {
			end = now
		}
		buckets[i] = GuestSponsorApprovalBucket{
			Start: start.Format(time.RFC3339),
			End:   end.Format(time.RFC3339),
		}
	}

	summary := GuestSponsorApprovalSummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketDuration.Minutes()),
		Buckets:       buckets,
	}

	sponsorStats := map[string]*GuestSponsorApprovalSponsorStats{}
	companyCounts := map[string]int{}
	sponsorSet := map[string]struct{}{}
	companySet := map[string]struct{}{}
	var approvalMinutesTotal int64
	var approvalSamples int64
	var pendingMinutesTotal int64
	var pendingSamples int64

	for _, item := range rows {
		summary.TotalRecords++

		approvalStatusName := guestDeliveryStatusName(item.ApprovalDeliveryStatus, "unknown")
		if !guestDeliveryRequiresSponsorApproval(approvalStatusName) {
			continue
		}

		summary.SponsorApprovalRequiredCount++

		statusName := strings.ToLower(strings.TrimSpace(item.Status))
		sponsorName := guestSponsorAnalyticsLabel(item)
		stats := sponsorStats[sponsorName]
		if stats == nil {
			stats = &GuestSponsorApprovalSponsorStats{Name: sponsorName}
			sponsorStats[sponsorName] = stats
		}

		sponsorSet[strings.ToLower(sponsorName)] = struct{}{}
		if companyName := strings.TrimSpace(item.Company); companyName != "" {
			companyCounts[companyName]++
			companySet[strings.ToLower(companyName)] = struct{}{}
		}

		createdAt := parseSessionAnalyticsTime(item.CreatedAt)
		approvedAt := parseSessionAnalyticsTime(item.ApprovedAt)
		rejectedAt := parseSessionAnalyticsTime(item.RejectedAt)
		completedAt := parseSessionAnalyticsTime(item.CompletedAt)

		if !createdAt.IsZero() {
			createdText := createdAt.Format(time.RFC3339)
			if summary.LatestSubmittedAt == "" || createdText > summary.LatestSubmittedAt {
				summary.LatestSubmittedAt = createdText
			}
			if stats.LatestSubmittedAt == "" || createdText > stats.LatestSubmittedAt {
				stats.LatestSubmittedAt = createdText
			}
			if !createdAt.Before(cutoff) {
				buckets[bucketIndex(createdAt, cutoff, bucketDuration, bucketCount)].SubmittedCount++
			}
		}

		switch statusName {
		case "pending":
			summary.PendingSponsorApprovalCount++
			stats.PendingCount++
			if !createdAt.IsZero() && !now.Before(createdAt) {
				pendingMinutes := int64(now.Sub(createdAt).Minutes())
				pendingMinutesTotal += pendingMinutes
				pendingSamples++
				if pendingMinutes > summary.MaxPendingApprovalMinutes {
					summary.MaxPendingApprovalMinutes = pendingMinutes
				}
				if pendingMinutes >= guestSponsorPending30Minutes {
					summary.PendingOlderThan30MinutesCount++
					stats.OlderThan30MinutesCount++
				}
				if pendingMinutes >= guestSponsorPending4Hours {
					summary.PendingOlderThan4HoursCount++
					stats.OlderThan4HoursCount++
				}
				if pendingMinutes >= guestSponsorPending24Hours {
					summary.PendingOlderThan24HoursCount++
					stats.OlderThan24HoursCount++
				}
				if !createdAt.Before(cutoff) {
					idx := bucketIndex(createdAt, cutoff, bucketDuration, bucketCount)
					buckets[idx].PendingSponsorApprovalCount++
					if pendingMinutes >= guestSponsorPending30Minutes {
						buckets[idx].PendingOlderThan30MinutesCount++
					}
					if pendingMinutes >= guestSponsorPending4Hours {
						buckets[idx].PendingOlderThan4HoursCount++
					}
					if pendingMinutes >= guestSponsorPending24Hours {
						buckets[idx].PendingOlderThan24HoursCount++
					}
				}
			}
		case "approved":
			summary.ApprovedWithSponsorCount++
			stats.ApprovedCount++
		case "rejected":
			summary.RejectedWithSponsorCount++
			stats.RejectedCount++
		case "completed":
			summary.CompletedWithSponsorCount++
			stats.CompletedCount++
		}

		if !approvedAt.IsZero() {
			approvedText := approvedAt.Format(time.RFC3339)
			if summary.LatestApprovedAt == "" || approvedText > summary.LatestApprovedAt {
				summary.LatestApprovedAt = approvedText
			}
			if stats.LatestApprovedAt == "" || approvedText > stats.LatestApprovedAt {
				stats.LatestApprovedAt = approvedText
			}
			if !approvedAt.Before(cutoff) {
				buckets[bucketIndex(approvedAt, cutoff, bucketDuration, bucketCount)].ApprovedCount++
			}
			if !createdAt.IsZero() && approvedAt.After(createdAt) {
				approvalMinutes := int64(approvedAt.Sub(createdAt).Minutes())
				approvalMinutesTotal += approvalMinutes
				approvalSamples++
				if approvalMinutes > summary.MaxApprovalMinutes {
					summary.MaxApprovalMinutes = approvalMinutes
				}
				stats.approvalMinutesTotal += approvalMinutes
				stats.approvalSamples++
				if approvalMinutes > stats.MaxApprovalMinutes {
					stats.MaxApprovalMinutes = approvalMinutes
				}
			}
		}

		if !rejectedAt.IsZero() {
			rejectedText := rejectedAt.Format(time.RFC3339)
			if summary.LatestRejectedAt == "" || rejectedText > summary.LatestRejectedAt {
				summary.LatestRejectedAt = rejectedText
			}
			if !rejectedAt.Before(cutoff) {
				buckets[bucketIndex(rejectedAt, cutoff, bucketDuration, bucketCount)].RejectedCount++
			}
		}

		if !completedAt.IsZero() && !completedAt.Before(cutoff) {
			buckets[bucketIndex(completedAt, cutoff, bucketDuration, bucketCount)].CompletedCount++
		}
	}

	summary.UniqueSponsorsWindow = len(sponsorSet)
	summary.UniqueCompaniesWindow = len(companySet)
	if approvalSamples > 0 {
		summary.AvgApprovalMinutes = approvalMinutesTotal / approvalSamples
	}
	if pendingSamples > 0 {
		summary.AvgPendingApprovalMinutes = pendingMinutesTotal / pendingSamples
	}
	summary.Companies = sessionAnalyticsCounts(companyCounts)
	summary.Sponsors = guestSponsorAnalyticsSponsorList(sponsorStats)
	summary.Buckets = buckets

	return summary, nil
}

func guestSponsorAnalyticsLabel(item guestLifecycleRow) string {
	if label := strings.TrimSpace(guestDeliverySponsorLabel(item)); label != "" {
		return label
	}
	return "missing sponsor"
}

func guestSponsorAnalyticsSponsorList(values map[string]*GuestSponsorApprovalSponsorStats) []GuestSponsorApprovalSponsorStats {
	items := make([]GuestSponsorApprovalSponsorStats, 0, len(values))
	for _, item := range values {
		if item.approvalSamples > 0 {
			item.AvgApprovalMinutes = item.approvalMinutesTotal / item.approvalSamples
		}
		items = append(items, GuestSponsorApprovalSponsorStats{
			Name:                    item.Name,
			PendingCount:            item.PendingCount,
			ApprovedCount:           item.ApprovedCount,
			RejectedCount:           item.RejectedCount,
			CompletedCount:          item.CompletedCount,
			OlderThan30MinutesCount: item.OlderThan30MinutesCount,
			OlderThan4HoursCount:    item.OlderThan4HoursCount,
			OlderThan24HoursCount:   item.OlderThan24HoursCount,
			AvgApprovalMinutes:      item.AvgApprovalMinutes,
			MaxApprovalMinutes:      item.MaxApprovalMinutes,
			LatestSubmittedAt:       item.LatestSubmittedAt,
			LatestApprovedAt:        item.LatestApprovedAt,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].PendingCount != items[j].PendingCount {
			return items[i].PendingCount > items[j].PendingCount
		}
		if items[i].OlderThan24HoursCount != items[j].OlderThan24HoursCount {
			return items[i].OlderThan24HoursCount > items[j].OlderThan24HoursCount
		}
		if items[i].OlderThan4HoursCount != items[j].OlderThan4HoursCount {
			return items[i].OlderThan4HoursCount > items[j].OlderThan4HoursCount
		}
		if items[i].ApprovedCount != items[j].ApprovedCount {
			return items[i].ApprovedCount > items[j].ApprovedCount
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	return items
}
