package db

import (
	"fmt"
	"strings"
	"time"
)

type GuestDeliveryAnalyticsSummary struct {
	WindowHours                    int                            `json:"window_hours"`
	BucketCount                    int                            `json:"bucket_count"`
	BucketMinutes                  int                            `json:"bucket_minutes"`
	TotalRecords                   int                            `json:"total_records"`
	SponsorApprovalRequiredCount   int                            `json:"sponsor_approval_required_count"`
	PendingSponsorApprovalCount    int                            `json:"pending_sponsor_approval_count"`
	PendingInviteQueueCount        int                            `json:"pending_invite_queue_count"`
	ApprovalDeliveryPendingCount   int                            `json:"approval_delivery_pending_count"`
	ApprovalDeliverySentCount      int                            `json:"approval_delivery_sent_count"`
	ApprovalDeliveryFailedCount    int                            `json:"approval_delivery_failed_count"`
	InviteQueuedCount              int                            `json:"invite_queued_count"`
	InviteSentCount                int                            `json:"invite_sent_count"`
	InviteFailedCount              int                            `json:"invite_failed_count"`
	ApprovedCount                  int                            `json:"approved_count"`
	RejectedCount                  int                            `json:"rejected_count"`
	CompletedCount                 int                            `json:"completed_count"`
	UniqueGuestsWindow             int                            `json:"unique_guests_window"`
	UniqueSponsorsWindow           int                            `json:"unique_sponsors_window"`
	UniqueCompaniesWindow          int                            `json:"unique_companies_window"`
	AvgApprovalMinutes             int64                          `json:"avg_approval_minutes"`
	MaxApprovalMinutes             int64                          `json:"max_approval_minutes"`
	AvgApprovalToCompletionMinutes int64                          `json:"avg_approval_to_completion_minutes"`
	MaxApprovalToCompletionMinutes int64                          `json:"max_approval_to_completion_minutes"`
	LatestSubmittedAt              string                         `json:"latest_submitted_at"`
	LatestApprovedAt               string                         `json:"latest_approved_at"`
	LatestRejectedAt               string                         `json:"latest_rejected_at"`
	LatestCompletedAt              string                         `json:"latest_completed_at"`
	Sponsors                       []SessionAnalyticsCount        `json:"sponsors"`
	Companies                      []SessionAnalyticsCount        `json:"companies"`
	Roles                          []SessionAnalyticsCount        `json:"roles"`
	ApprovalDeliveryStatuses       []SessionAnalyticsCount        `json:"approval_delivery_statuses"`
	InviteDeliveryStatuses         []SessionAnalyticsCount        `json:"invite_delivery_statuses"`
	Buckets                        []GuestDeliveryAnalyticsBucket `json:"buckets"`
}

type GuestDeliveryAnalyticsBucket struct {
	Start                       string `json:"start"`
	End                         string `json:"end"`
	SubmittedCount              int    `json:"submitted_count"`
	PendingSponsorApprovalCount int    `json:"pending_sponsor_approval_count"`
	ApprovalDeliveryFailedCount int    `json:"approval_delivery_failed_count"`
	ApprovedCount               int    `json:"approved_count"`
	RejectedCount               int    `json:"rejected_count"`
	InviteQueuedCount           int    `json:"invite_queued_count"`
	InviteSentCount             int    `json:"invite_sent_count"`
	InviteFailedCount           int    `json:"invite_failed_count"`
	CompletedCount              int    `json:"completed_count"`
}

func GetGuestDeliveryAnalytics(query GuestLifecycleQuery) (GuestDeliveryAnalyticsSummary, error) {
	if DB == nil {
		return GuestDeliveryAnalyticsSummary{}, fmt.Errorf("database not initialized")
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
		return GuestDeliveryAnalyticsSummary{}, err
	}

	buckets := make([]GuestDeliveryAnalyticsBucket, bucketCount)
	for i := range buckets {
		start := cutoff.Add(time.Duration(i) * bucketDuration)
		end := start.Add(bucketDuration)
		if i == bucketCount-1 {
			end = now
		}
		buckets[i] = GuestDeliveryAnalyticsBucket{
			Start: start.Format(time.RFC3339),
			End:   end.Format(time.RFC3339),
		}
	}

	summary := GuestDeliveryAnalyticsSummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketDuration.Minutes()),
		Buckets:       buckets,
	}

	sponsorCounts := map[string]int{}
	companyCounts := map[string]int{}
	roleCounts := map[string]int{}
	approvalStatusCounts := map[string]int{}
	inviteStatusCounts := map[string]int{}
	guestSet := map[string]struct{}{}
	sponsorSet := map[string]struct{}{}
	companySet := map[string]struct{}{}
	var approvalMinutesTotal int64
	var approvalCount int64
	var approvalToCompletionMinutesTotal int64
	var approvalToCompletionCount int64

	for _, item := range rows {
		summary.TotalRecords++

		statusName := strings.ToLower(strings.TrimSpace(item.Status))
		switch statusName {
		case "approved":
			summary.ApprovedCount++
		case "rejected":
			summary.RejectedCount++
		case "completed":
			summary.CompletedCount++
		}

		approvalStatusName := guestDeliveryStatusName(item.ApprovalDeliveryStatus, "unknown")
		approvalStatusCounts[approvalStatusName]++
		switch approvalStatusName {
		case "pending":
			summary.SponsorApprovalRequiredCount++
			summary.ApprovalDeliveryPendingCount++
		case "sent":
			summary.SponsorApprovalRequiredCount++
			summary.ApprovalDeliverySentCount++
		case "failed":
			summary.SponsorApprovalRequiredCount++
			summary.ApprovalDeliveryFailedCount++
		}
		if statusName == "pending" && guestDeliveryRequiresSponsorApproval(approvalStatusName) {
			summary.PendingSponsorApprovalCount++
		}

		inviteStatusName := guestDeliveryStatusName(item.InviteDeliveryStatus, "unknown")
		inviteStatusCounts[inviteStatusName]++
		switch inviteStatusName {
		case "queued":
			summary.InviteQueuedCount++
			summary.PendingInviteQueueCount++
		case "sent":
			summary.InviteSentCount++
		case "failed":
			summary.InviteFailedCount++
		}

		if sponsorName := guestDeliverySponsorLabel(item); sponsorName != "" {
			sponsorCounts[sponsorName]++
		}

		companyName := strings.TrimSpace(item.Company)
		if companyName != "" {
			companyCounts[companyName]++
		}

		roleName := strings.TrimSpace(item.Role)
		if roleName == "" {
			roleName = "unassigned"
		}
		roleCounts[roleName]++

		createdAt := parseSessionAnalyticsTime(item.CreatedAt)
		approvedAt := parseSessionAnalyticsTime(item.ApprovedAt)
		rejectedAt := parseSessionAnalyticsTime(item.RejectedAt)
		completedAt := parseSessionAnalyticsTime(item.CompletedAt)
		inviteAt := guestDeliveryInviteAnchor(createdAt, approvedAt)

		if !createdAt.IsZero() {
			createdText := createdAt.Format(time.RFC3339)
			if summary.LatestSubmittedAt == "" || createdText > summary.LatestSubmittedAt {
				summary.LatestSubmittedAt = createdText
			}
			if !createdAt.Before(cutoff) {
				buckets[bucketIndex(createdAt, cutoff, bucketDuration, bucketCount)].SubmittedCount++
				if statusName == "pending" && guestDeliveryRequiresSponsorApproval(approvalStatusName) {
					buckets[bucketIndex(createdAt, cutoff, bucketDuration, bucketCount)].PendingSponsorApprovalCount++
				}
				if approvalStatusName == "failed" {
					buckets[bucketIndex(createdAt, cutoff, bucketDuration, bucketCount)].ApprovalDeliveryFailedCount++
				}
				guestSet[guestLifecycleGuestKey(item)] = struct{}{}
				if sponsorKey := guestLifecycleSponsorKey(item); sponsorKey != "" {
					sponsorSet[sponsorKey] = struct{}{}
				}
				if companyKey := strings.TrimSpace(item.Company); companyKey != "" {
					companySet[strings.ToLower(companyKey)] = struct{}{}
				}
			}
		}

		if !approvedAt.IsZero() {
			approvedText := approvedAt.Format(time.RFC3339)
			if summary.LatestApprovedAt == "" || approvedText > summary.LatestApprovedAt {
				summary.LatestApprovedAt = approvedText
			}
			if !approvedAt.Before(cutoff) {
				buckets[bucketIndex(approvedAt, cutoff, bucketDuration, bucketCount)].ApprovedCount++
			}
			if !createdAt.IsZero() && approvedAt.After(createdAt) {
				approvalMinutes := int64(approvedAt.Sub(createdAt).Minutes())
				approvalMinutesTotal += approvalMinutes
				approvalCount++
				if approvalMinutes > summary.MaxApprovalMinutes {
					summary.MaxApprovalMinutes = approvalMinutes
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

		if !inviteAt.IsZero() && !inviteAt.Before(cutoff) {
			idx := bucketIndex(inviteAt, cutoff, bucketDuration, bucketCount)
			switch inviteStatusName {
			case "queued":
				buckets[idx].InviteQueuedCount++
			case "sent":
				buckets[idx].InviteSentCount++
			case "failed":
				buckets[idx].InviteFailedCount++
			}
		}

		if !completedAt.IsZero() {
			completedText := completedAt.Format(time.RFC3339)
			if summary.LatestCompletedAt == "" || completedText > summary.LatestCompletedAt {
				summary.LatestCompletedAt = completedText
			}
			if !completedAt.Before(cutoff) {
				buckets[bucketIndex(completedAt, cutoff, bucketDuration, bucketCount)].CompletedCount++
			}
			if !approvedAt.IsZero() && completedAt.After(approvedAt) {
				approvalToCompletionMinutes := int64(completedAt.Sub(approvedAt).Minutes())
				approvalToCompletionMinutesTotal += approvalToCompletionMinutes
				approvalToCompletionCount++
				if approvalToCompletionMinutes > summary.MaxApprovalToCompletionMinutes {
					summary.MaxApprovalToCompletionMinutes = approvalToCompletionMinutes
				}
			}
		}
	}

	summary.UniqueGuestsWindow = len(guestSet)
	summary.UniqueSponsorsWindow = len(sponsorSet)
	summary.UniqueCompaniesWindow = len(companySet)
	if approvalCount > 0 {
		summary.AvgApprovalMinutes = approvalMinutesTotal / approvalCount
	}
	if approvalToCompletionCount > 0 {
		summary.AvgApprovalToCompletionMinutes = approvalToCompletionMinutesTotal / approvalToCompletionCount
	}
	summary.Sponsors = sessionAnalyticsCounts(sponsorCounts)
	summary.Companies = sessionAnalyticsCounts(companyCounts)
	summary.Roles = sessionAnalyticsCounts(roleCounts)
	summary.ApprovalDeliveryStatuses = sessionAnalyticsCounts(approvalStatusCounts)
	summary.InviteDeliveryStatuses = sessionAnalyticsCounts(inviteStatusCounts)
	summary.Buckets = buckets

	return summary, nil
}

func guestDeliveryStatusName(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
}

func guestDeliveryRequiresSponsorApproval(status string) bool {
	switch status {
	case "pending", "sent", "failed":
		return true
	default:
		return false
	}
}

func guestDeliverySponsorLabel(item guestLifecycleRow) string {
	if email := strings.TrimSpace(item.SponsorEmail); email != "" {
		return email
	}
	if name := strings.TrimSpace(item.SponsorName); name != "" {
		return name
	}
	if phone := strings.TrimSpace(item.SponsorPhone); phone != "" {
		return phone
	}
	return ""
}

func guestDeliveryInviteAnchor(createdAt, approvedAt time.Time) time.Time {
	if !approvedAt.IsZero() {
		return approvedAt
	}
	return createdAt
}
