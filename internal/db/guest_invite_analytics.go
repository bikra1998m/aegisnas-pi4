package db

import (
	"fmt"
	"strings"
	"time"
)

type GuestInviteAnalyticsSummary struct {
	WindowHours                  int                          `json:"window_hours"`
	BucketCount                  int                          `json:"bucket_count"`
	BucketMinutes                int                          `json:"bucket_minutes"`
	TotalRecords                 int                          `json:"total_records"`
	TrackedInviteRecordsCount    int                          `json:"tracked_invite_records_count"`
	InviteQueuedCount            int                          `json:"invite_queued_count"`
	InviteSentCount              int                          `json:"invite_sent_count"`
	InviteFailedCount            int                          `json:"invite_failed_count"`
	InviteNotRequestedCount      int                          `json:"invite_not_requested_count"`
	CompletedAfterInviteCount    int                          `json:"completed_after_invite_count"`
	UniqueGuestsWindow           int                          `json:"unique_guests_window"`
	UniqueSponsorsWindow         int                          `json:"unique_sponsors_window"`
	UniqueCompaniesWindow        int                          `json:"unique_companies_window"`
	AvgApprovalToInviteMinutes   int64                        `json:"avg_approval_to_invite_minutes"`
	MaxApprovalToInviteMinutes   int64                        `json:"max_approval_to_invite_minutes"`
	AvgInviteToCompletionMinutes int64                        `json:"avg_invite_to_completion_minutes"`
	MaxInviteToCompletionMinutes int64                        `json:"max_invite_to_completion_minutes"`
	LatestInviteQueuedAt         string                       `json:"latest_invite_queued_at"`
	LatestInviteSentAt           string                       `json:"latest_invite_sent_at"`
	LatestInviteFailedAt         string                       `json:"latest_invite_failed_at"`
	LatestInviteCompletedAt      string                       `json:"latest_invite_completed_at"`
	Sponsors                     []SessionAnalyticsCount      `json:"sponsors"`
	Companies                    []SessionAnalyticsCount      `json:"companies"`
	Roles                        []SessionAnalyticsCount      `json:"roles"`
	InviteDeliveryStatuses       []SessionAnalyticsCount      `json:"invite_delivery_statuses"`
	InviteFailureReasons         []SessionAnalyticsCount      `json:"invite_failure_reasons"`
	Buckets                      []GuestInviteAnalyticsBucket `json:"buckets"`
}

type GuestInviteAnalyticsBucket struct {
	Start                     string `json:"start"`
	End                       string `json:"end"`
	InviteQueuedCount         int    `json:"invite_queued_count"`
	InviteSentCount           int    `json:"invite_sent_count"`
	InviteFailedCount         int    `json:"invite_failed_count"`
	CompletedAfterInviteCount int    `json:"completed_after_invite_count"`
}

func GetGuestInviteAnalytics(query GuestLifecycleQuery) (GuestInviteAnalyticsSummary, error) {
	if DB == nil {
		return GuestInviteAnalyticsSummary{}, fmt.Errorf("database not initialized")
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
		return GuestInviteAnalyticsSummary{}, err
	}

	buckets := make([]GuestInviteAnalyticsBucket, bucketCount)
	for i := range buckets {
		start := cutoff.Add(time.Duration(i) * bucketDuration)
		end := start.Add(bucketDuration)
		if i == bucketCount-1 {
			end = now
		}
		buckets[i] = GuestInviteAnalyticsBucket{
			Start: start.Format(time.RFC3339),
			End:   end.Format(time.RFC3339),
		}
	}

	summary := GuestInviteAnalyticsSummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketDuration.Minutes()),
		Buckets:       buckets,
	}

	sponsorCounts := map[string]int{}
	companyCounts := map[string]int{}
	roleCounts := map[string]int{}
	inviteStatusCounts := map[string]int{}
	inviteFailureReasonCounts := map[string]int{}
	guestSet := map[string]struct{}{}
	sponsorSet := map[string]struct{}{}
	companySet := map[string]struct{}{}
	var approvalToInviteMinutesTotal int64
	var approvalToInviteSamples int64
	var inviteToCompletionMinutesTotal int64
	var inviteToCompletionSamples int64

	for _, item := range rows {
		summary.TotalRecords++

		createdAt := parseSessionAnalyticsTime(item.CreatedAt)
		updatedAt := parseSessionAnalyticsTime(item.UpdatedAt)
		approvedAt := parseSessionAnalyticsTime(item.ApprovedAt)
		completedAt := parseSessionAnalyticsTime(item.CompletedAt)
		inviteStatus := guestDeliveryStatusName(item.InviteDeliveryStatus, "unknown")
		inviteStatusCounts[inviteStatus]++

		switch inviteStatus {
		case "queued":
			summary.InviteQueuedCount++
		case "sent":
			summary.InviteSentCount++
		case "failed":
			summary.InviteFailedCount++
			inviteFailureReasonCounts[guestDeliveryFailureErrorName(item.InviteDeliveryError)]++
		case "not_requested":
			summary.InviteNotRequestedCount++
		}

		if inviteStatus == "queued" || inviteStatus == "sent" || inviteStatus == "failed" {
			summary.TrackedInviteRecordsCount++
		}

		roleName := strings.TrimSpace(item.Role)
		if roleName == "" {
			roleName = "unassigned"
		}
		sponsorName := guestDeliverySponsorLabel(item)
		companyName := strings.TrimSpace(item.Company)
		inviteAnchor := guestDeliveryInviteAnchor(createdAt, approvedAt)
		inviteEventAt := guestDeliveryFailureEventTime(updatedAt, inviteAnchor)
		trackedInvite := inviteStatus == "queued" || inviteStatus == "sent" || inviteStatus == "failed"

		if trackedInvite {
			roleCounts[roleName]++
			if sponsorName != "" {
				sponsorCounts[sponsorName]++
			}
			if companyName != "" {
				companyCounts[companyName]++
			}
		}

		if trackedInvite {
			referenceAt := inviteAnchor
			if referenceAt.IsZero() {
				referenceAt = inviteEventAt
			}
			if referenceAt.IsZero() {
				referenceAt = createdAt
			}
			if !referenceAt.IsZero() && !referenceAt.Before(cutoff) {
				guestSet[guestLifecycleGuestKey(item)] = struct{}{}
				if sponsorKey := guestLifecycleSponsorKey(item); sponsorKey != "" {
					sponsorSet[sponsorKey] = struct{}{}
				}
				if companyName != "" {
					companySet[strings.ToLower(companyName)] = struct{}{}
				}
			}
		}

		if trackedInvite && !approvedAt.IsZero() && !inviteEventAt.IsZero() && inviteEventAt.After(approvedAt) {
			minutes := int64(inviteEventAt.Sub(approvedAt).Minutes())
			approvalToInviteMinutesTotal += minutes
			approvalToInviteSamples++
			if minutes > summary.MaxApprovalToInviteMinutes {
				summary.MaxApprovalToInviteMinutes = minutes
			}
		}

		switch inviteStatus {
		case "queued":
			queuedText := guestDeliveryIssueTimeText(inviteAnchor)
			summary.LatestInviteQueuedAt = guestDeliveryLatestTimestamp(summary.LatestInviteQueuedAt, queuedText)
			if !inviteAnchor.IsZero() && !inviteAnchor.Before(cutoff) {
				buckets[bucketIndex(inviteAnchor, cutoff, bucketDuration, bucketCount)].InviteQueuedCount++
			}
		case "sent":
			sentText := guestDeliveryIssueTimeText(inviteEventAt)
			summary.LatestInviteSentAt = guestDeliveryLatestTimestamp(summary.LatestInviteSentAt, sentText)
			if !inviteEventAt.IsZero() && !inviteEventAt.Before(cutoff) {
				buckets[bucketIndex(inviteEventAt, cutoff, bucketDuration, bucketCount)].InviteSentCount++
			}
		case "failed":
			failedText := guestDeliveryIssueTimeText(inviteEventAt)
			summary.LatestInviteFailedAt = guestDeliveryLatestTimestamp(summary.LatestInviteFailedAt, failedText)
			if !inviteEventAt.IsZero() && !inviteEventAt.Before(cutoff) {
				buckets[bucketIndex(inviteEventAt, cutoff, bucketDuration, bucketCount)].InviteFailedCount++
			}
		}

		if inviteStatus == "sent" && !completedAt.IsZero() {
			summary.CompletedAfterInviteCount++
			completedText := guestDeliveryIssueTimeText(completedAt)
			summary.LatestInviteCompletedAt = guestDeliveryLatestTimestamp(summary.LatestInviteCompletedAt, completedText)
			if !completedAt.Before(cutoff) {
				buckets[bucketIndex(completedAt, cutoff, bucketDuration, bucketCount)].CompletedAfterInviteCount++
			}
			if !inviteEventAt.IsZero() && completedAt.After(inviteEventAt) {
				minutes := int64(completedAt.Sub(inviteEventAt).Minutes())
				inviteToCompletionMinutesTotal += minutes
				inviteToCompletionSamples++
				if minutes > summary.MaxInviteToCompletionMinutes {
					summary.MaxInviteToCompletionMinutes = minutes
				}
			}
		}
	}

	summary.UniqueGuestsWindow = len(guestSet)
	summary.UniqueSponsorsWindow = len(sponsorSet)
	summary.UniqueCompaniesWindow = len(companySet)
	if approvalToInviteSamples > 0 {
		summary.AvgApprovalToInviteMinutes = approvalToInviteMinutesTotal / approvalToInviteSamples
	}
	if inviteToCompletionSamples > 0 {
		summary.AvgInviteToCompletionMinutes = inviteToCompletionMinutesTotal / inviteToCompletionSamples
	}
	summary.Sponsors = sessionAnalyticsCounts(sponsorCounts)
	summary.Companies = sessionAnalyticsCounts(companyCounts)
	summary.Roles = sessionAnalyticsCounts(roleCounts)
	summary.InviteDeliveryStatuses = sessionAnalyticsCounts(inviteStatusCounts)
	summary.InviteFailureReasons = sessionAnalyticsCounts(inviteFailureReasonCounts)
	summary.Buckets = buckets

	return summary, nil
}
