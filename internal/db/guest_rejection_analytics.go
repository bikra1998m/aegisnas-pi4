package db

import (
	"fmt"
	"strings"
	"time"
)

type GuestRejectionAnalyticsSummary struct {
	WindowHours                  int                     `json:"window_hours"`
	BucketCount                  int                     `json:"bucket_count"`
	BucketMinutes                int                     `json:"bucket_minutes"`
	TotalRecords                 int                     `json:"total_records"`
	RejectedCount                int                     `json:"rejected_count"`
	RejectedWithSponsorCount     int                     `json:"rejected_with_sponsor_count"`
	RejectedWithoutSponsorCount  int                     `json:"rejected_without_sponsor_count"`
	RejectedAfterApprovalCount   int                     `json:"rejected_after_approval_count"`
	RejectedBeforeApprovalCount  int                     `json:"rejected_before_approval_count"`
	UniqueRejectionReasonsWindow int                     `json:"unique_rejection_reasons_window"`
	UniqueSponsorsWindow         int                     `json:"unique_sponsors_window"`
	UniqueCompaniesWindow        int                     `json:"unique_companies_window"`
	AvgSubmitToRejectionMinutes  int64                   `json:"avg_submit_to_rejection_minutes"`
	MaxSubmitToRejectionMinutes  int64                   `json:"max_submit_to_rejection_minutes"`
	LatestRejectedAt             string                  `json:"latest_rejected_at"`
	RejectionReasons             []SessionAnalyticsCount `json:"rejection_reasons"`
	Sponsors                     []SessionAnalyticsCount `json:"sponsors"`
	Companies                    []SessionAnalyticsCount `json:"companies"`
	Roles                        []SessionAnalyticsCount `json:"roles"`
	Buckets                      []GuestRejectionBucket  `json:"buckets"`
}

type GuestRejectionBucket struct {
	Start                       string `json:"start"`
	End                         string `json:"end"`
	RejectedCount               int    `json:"rejected_count"`
	RejectedWithSponsorCount    int    `json:"rejected_with_sponsor_count"`
	RejectedWithoutSponsorCount int    `json:"rejected_without_sponsor_count"`
	RejectedAfterApprovalCount  int    `json:"rejected_after_approval_count"`
}

func GetGuestRejectionAnalytics(query GuestLifecycleQuery) (GuestRejectionAnalyticsSummary, error) {
	if DB == nil {
		return GuestRejectionAnalyticsSummary{}, fmt.Errorf("database not initialized")
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
		return GuestRejectionAnalyticsSummary{}, err
	}

	buckets := make([]GuestRejectionBucket, bucketCount)
	for i := range buckets {
		start := cutoff.Add(time.Duration(i) * bucketDuration)
		end := start.Add(bucketDuration)
		if i == bucketCount-1 {
			end = now
		}
		buckets[i] = GuestRejectionBucket{
			Start: start.Format(time.RFC3339),
			End:   end.Format(time.RFC3339),
		}
	}

	summary := GuestRejectionAnalyticsSummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketDuration.Minutes()),
		Buckets:       buckets,
	}

	reasonCounts := map[string]int{}
	sponsorCounts := map[string]int{}
	companyCounts := map[string]int{}
	roleCounts := map[string]int{}
	reasonSet := map[string]struct{}{}
	sponsorSet := map[string]struct{}{}
	companySet := map[string]struct{}{}
	var submitToRejectionTotal int64
	var submitToRejectionSamples int64

	for _, item := range rows {
		summary.TotalRecords++

		statusName := strings.ToLower(strings.TrimSpace(item.Status))
		createdAt := parseSessionAnalyticsTime(item.CreatedAt)
		updatedAt := parseSessionAnalyticsTime(item.UpdatedAt)
		approvedAt := parseSessionAnalyticsTime(item.ApprovedAt)
		rejectedAt := parseSessionAnalyticsTime(item.RejectedAt)

		rejectedReached := !rejectedAt.IsZero() || statusName == "rejected"
		if !rejectedReached {
			continue
		}

		summary.RejectedCount++

		reasonName := strings.TrimSpace(item.RejectionReason)
		if reasonName == "" {
			reasonName = "unspecified"
		}
		reasonCounts[reasonName]++
		reasonSet[strings.ToLower(reasonName)] = struct{}{}

		if roleName := strings.TrimSpace(item.Role); roleName != "" {
			roleCounts[roleName]++
		} else {
			roleCounts["unassigned"]++
		}

		sponsorName := guestDeliverySponsorLabel(item)
		if sponsorName != "" {
			summary.RejectedWithSponsorCount++
			sponsorCounts[sponsorName]++
			sponsorSet[strings.ToLower(sponsorName)] = struct{}{}
		} else {
			summary.RejectedWithoutSponsorCount++
		}
		if companyName := strings.TrimSpace(item.Company); companyName != "" {
			companyCounts[companyName]++
			companySet[strings.ToLower(companyName)] = struct{}{}
		}

		rejectionEventAt := guestRejectionEventTime(rejectedAt, updatedAt, createdAt)
		rejectionText := guestRejectionTimeText(rejectionEventAt)
		if summary.LatestRejectedAt == "" || rejectionText > summary.LatestRejectedAt {
			summary.LatestRejectedAt = rejectionText
		}

		if !createdAt.IsZero() && !rejectionEventAt.IsZero() && rejectionEventAt.After(createdAt) {
			minutes := int64(rejectionEventAt.Sub(createdAt).Minutes())
			submitToRejectionTotal += minutes
			submitToRejectionSamples++
			if minutes > summary.MaxSubmitToRejectionMinutes {
				summary.MaxSubmitToRejectionMinutes = minutes
			}
		}

		afterApproval := !approvedAt.IsZero() && !rejectionEventAt.IsZero() && rejectionEventAt.After(approvedAt)
		if afterApproval {
			summary.RejectedAfterApprovalCount++
		} else {
			summary.RejectedBeforeApprovalCount++
		}

		if !rejectionEventAt.IsZero() && !rejectionEventAt.Before(cutoff) {
			idx := bucketIndex(rejectionEventAt, cutoff, bucketDuration, bucketCount)
			buckets[idx].RejectedCount++
			if sponsorName != "" {
				buckets[idx].RejectedWithSponsorCount++
			} else {
				buckets[idx].RejectedWithoutSponsorCount++
			}
			if afterApproval {
				buckets[idx].RejectedAfterApprovalCount++
			}
		}
	}

	summary.UniqueRejectionReasonsWindow = len(reasonSet)
	summary.UniqueSponsorsWindow = len(sponsorSet)
	summary.UniqueCompaniesWindow = len(companySet)
	if submitToRejectionSamples > 0 {
		summary.AvgSubmitToRejectionMinutes = submitToRejectionTotal / submitToRejectionSamples
	}
	summary.RejectionReasons = sessionAnalyticsCounts(reasonCounts)
	summary.Sponsors = sessionAnalyticsCounts(sponsorCounts)
	summary.Companies = sessionAnalyticsCounts(companyCounts)
	summary.Roles = sessionAnalyticsCounts(roleCounts)
	summary.Buckets = buckets

	return summary, nil
}

func guestRejectionEventTime(rejectedAt, updatedAt, createdAt time.Time) time.Time {
	if !rejectedAt.IsZero() {
		return rejectedAt
	}
	if !updatedAt.IsZero() {
		return updatedAt
	}
	return createdAt
}

func guestRejectionTimeText(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
