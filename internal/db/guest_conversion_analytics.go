package db

import (
	"fmt"
	"strings"
	"time"
)

type GuestConversionSummary struct {
	WindowHours                    int                     `json:"window_hours"`
	BucketCount                    int                     `json:"bucket_count"`
	BucketMinutes                  int                     `json:"bucket_minutes"`
	TotalRecords                   int                     `json:"total_records"`
	OpenPendingCount               int                     `json:"open_pending_count"`
	SponsorApprovalRequiredCount   int                     `json:"sponsor_approval_required_count"`
	ApprovedStageCount             int                     `json:"approved_stage_count"`
	RejectedStageCount             int                     `json:"rejected_stage_count"`
	InviteQueuedCount              int                     `json:"invite_queued_count"`
	InviteSentCount                int                     `json:"invite_sent_count"`
	InviteFailedCount              int                     `json:"invite_failed_count"`
	CompletedStageCount            int                     `json:"completed_stage_count"`
	ApprovedWithoutSuccessfulInviteCount int               `json:"approved_without_successful_invite_count"`
	InvitedNotCompletedCount       int                     `json:"invited_not_completed_count"`
	CompletedAfterInviteCount      int                     `json:"completed_after_invite_count"`
	UniqueGuestsWindow             int                     `json:"unique_guests_window"`
	UniqueSponsorsWindow           int                     `json:"unique_sponsors_window"`
	UniqueCompaniesWindow          int                     `json:"unique_companies_window"`
	ApprovalRatePercent            int                     `json:"approval_rate_percent"`
	InviteSendRatePercent          int                     `json:"invite_send_rate_percent"`
	InviteCompletionRatePercent    int                     `json:"invite_completion_rate_percent"`
	EndToEndCompletionRatePercent  int                     `json:"end_to_end_completion_rate_percent"`
	AvgSubmitToApprovalMinutes     int64                   `json:"avg_submit_to_approval_minutes"`
	MaxSubmitToApprovalMinutes     int64                   `json:"max_submit_to_approval_minutes"`
	AvgSubmitToInviteMinutes       int64                   `json:"avg_submit_to_invite_minutes"`
	MaxSubmitToInviteMinutes       int64                   `json:"max_submit_to_invite_minutes"`
	AvgSubmitToCompletionMinutes   int64                   `json:"avg_submit_to_completion_minutes"`
	MaxSubmitToCompletionMinutes   int64                   `json:"max_submit_to_completion_minutes"`
	LatestSubmittedAt              string                  `json:"latest_submitted_at"`
	LatestApprovedAt               string                  `json:"latest_approved_at"`
	LatestInviteSentAt             string                  `json:"latest_invite_sent_at"`
	LatestCompletedAt              string                  `json:"latest_completed_at"`
	Roles                          []SessionAnalyticsCount `json:"roles"`
	Sponsors                       []SessionAnalyticsCount `json:"sponsors"`
	Companies                      []SessionAnalyticsCount `json:"companies"`
	Buckets                        []GuestConversionBucket `json:"buckets"`
}

type GuestConversionBucket struct {
	Start          string `json:"start"`
	End            string `json:"end"`
	SubmittedCount int    `json:"submitted_count"`
	ApprovedCount  int    `json:"approved_count"`
	RejectedCount  int    `json:"rejected_count"`
	InviteSentCount int   `json:"invite_sent_count"`
	CompletedCount int    `json:"completed_count"`
}

func GetGuestConversionAnalytics(query GuestLifecycleQuery) (GuestConversionSummary, error) {
	if DB == nil {
		return GuestConversionSummary{}, fmt.Errorf("database not initialized")
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
		return GuestConversionSummary{}, err
	}

	buckets := make([]GuestConversionBucket, bucketCount)
	for i := range buckets {
		start := cutoff.Add(time.Duration(i) * bucketDuration)
		end := start.Add(bucketDuration)
		if i == bucketCount-1 {
			end = now
		}
		buckets[i] = GuestConversionBucket{
			Start: start.Format(time.RFC3339),
			End:   end.Format(time.RFC3339),
		}
	}

	summary := GuestConversionSummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketDuration.Minutes()),
		Buckets:       buckets,
	}

	roleCounts := map[string]int{}
	sponsorCounts := map[string]int{}
	companyCounts := map[string]int{}
	guestSet := map[string]struct{}{}
	sponsorSet := map[string]struct{}{}
	companySet := map[string]struct{}{}

	var submitToApprovalTotal int64
	var submitToApprovalSamples int64
	var submitToInviteTotal int64
	var submitToInviteSamples int64
	var submitToCompletionTotal int64
	var submitToCompletionSamples int64

	for _, item := range rows {
		summary.TotalRecords++

		statusName := strings.ToLower(strings.TrimSpace(item.Status))
		inviteStatus := guestDeliveryStatusName(item.InviteDeliveryStatus, "unknown")
		approvalDeliveryStatus := guestDeliveryStatusName(item.ApprovalDeliveryStatus, "unknown")
		createdAt := parseSessionAnalyticsTime(item.CreatedAt)
		updatedAt := parseSessionAnalyticsTime(item.UpdatedAt)
		approvedAt := parseSessionAnalyticsTime(item.ApprovedAt)
		rejectedAt := parseSessionAnalyticsTime(item.RejectedAt)
		completedAt := parseSessionAnalyticsTime(item.CompletedAt)

		roleName := strings.TrimSpace(item.Role)
		if roleName == "" {
			roleName = "unassigned"
		}
		roleCounts[roleName]++
		if sponsorName := guestDeliverySponsorLabel(item); sponsorName != "" {
			sponsorCounts[sponsorName]++
			sponsorSet[strings.ToLower(sponsorName)] = struct{}{}
		}
		if companyName := strings.TrimSpace(item.Company); companyName != "" {
			companyCounts[companyName]++
			companySet[strings.ToLower(companyName)] = struct{}{}
		}

		guestSet[guestLifecycleGuestKey(item)] = struct{}{}

		if !createdAt.IsZero() {
			createdText := createdAt.Format(time.RFC3339)
			if summary.LatestSubmittedAt == "" || createdText > summary.LatestSubmittedAt {
				summary.LatestSubmittedAt = createdText
			}
			if !createdAt.Before(cutoff) {
				buckets[bucketIndex(createdAt, cutoff, bucketDuration, bucketCount)].SubmittedCount++
			}
		}

		approvedReached := !approvedAt.IsZero() || statusName == "approved" || statusName == "completed"
		rejectedReached := !rejectedAt.IsZero() || statusName == "rejected"
		completedReached := !completedAt.IsZero() || statusName == "completed"

		if statusName == "pending" {
			summary.OpenPendingCount++
		}
		if guestDeliveryRequiresSponsorApproval(approvalDeliveryStatus) {
			summary.SponsorApprovalRequiredCount++
		}
		if approvedReached {
			summary.ApprovedStageCount++
			if !approvedAt.IsZero() {
				approvedText := approvedAt.Format(time.RFC3339)
				if summary.LatestApprovedAt == "" || approvedText > summary.LatestApprovedAt {
					summary.LatestApprovedAt = approvedText
				}
				if !approvedAt.Before(cutoff) {
					buckets[bucketIndex(approvedAt, cutoff, bucketDuration, bucketCount)].ApprovedCount++
				}
				if !createdAt.IsZero() && approvedAt.After(createdAt) {
					minutes := int64(approvedAt.Sub(createdAt).Minutes())
					submitToApprovalTotal += minutes
					submitToApprovalSamples++
					if minutes > summary.MaxSubmitToApprovalMinutes {
						summary.MaxSubmitToApprovalMinutes = minutes
					}
				}
			}
		}
		if rejectedReached {
			summary.RejectedStageCount++
			if !rejectedAt.IsZero() && !rejectedAt.Before(cutoff) {
				buckets[bucketIndex(rejectedAt, cutoff, bucketDuration, bucketCount)].RejectedCount++
			}
		}
		if completedReached {
			summary.CompletedStageCount++
			if !completedAt.IsZero() {
				completedText := completedAt.Format(time.RFC3339)
				if summary.LatestCompletedAt == "" || completedText > summary.LatestCompletedAt {
					summary.LatestCompletedAt = completedText
				}
				if !completedAt.Before(cutoff) {
					buckets[bucketIndex(completedAt, cutoff, bucketDuration, bucketCount)].CompletedCount++
				}
				if !createdAt.IsZero() && completedAt.After(createdAt) {
					minutes := int64(completedAt.Sub(createdAt).Minutes())
					submitToCompletionTotal += minutes
					submitToCompletionSamples++
					if minutes > summary.MaxSubmitToCompletionMinutes {
						summary.MaxSubmitToCompletionMinutes = minutes
					}
				}
			}
		}

		inviteAnchor := guestDeliveryInviteAnchor(createdAt, approvedAt)
		inviteSentAt := time.Time{}
		switch inviteStatus {
		case "queued":
			summary.InviteQueuedCount++
		case "sent":
			summary.InviteSentCount++
			inviteSentAt = guestDeliveryFailureEventTime(updatedAt, inviteAnchor)
			if inviteSentAt.IsZero() {
				inviteSentAt = inviteAnchor
			}
			if !inviteSentAt.IsZero() {
				inviteText := inviteSentAt.Format(time.RFC3339)
				if summary.LatestInviteSentAt == "" || inviteText > summary.LatestInviteSentAt {
					summary.LatestInviteSentAt = inviteText
				}
				if !inviteSentAt.Before(cutoff) {
					buckets[bucketIndex(inviteSentAt, cutoff, bucketDuration, bucketCount)].InviteSentCount++
				}
				if !createdAt.IsZero() && inviteSentAt.After(createdAt) {
					minutes := int64(inviteSentAt.Sub(createdAt).Minutes())
					submitToInviteTotal += minutes
					submitToInviteSamples++
					if minutes > summary.MaxSubmitToInviteMinutes {
						summary.MaxSubmitToInviteMinutes = minutes
					}
				}
			}
		case "failed":
			summary.InviteFailedCount++
		}

		if approvedReached && inviteStatus != "sent" && !completedReached && !rejectedReached {
			summary.ApprovedWithoutSuccessfulInviteCount++
		}
		if inviteStatus == "sent" && !completedReached {
			summary.InvitedNotCompletedCount++
		}
		if inviteStatus == "sent" && completedReached {
			summary.CompletedAfterInviteCount++
		}
	}

	summary.UniqueGuestsWindow = len(guestSet)
	summary.UniqueSponsorsWindow = len(sponsorSet)
	summary.UniqueCompaniesWindow = len(companySet)
	summary.ApprovalRatePercent = guestConversionPercent(summary.ApprovedStageCount, summary.TotalRecords)
	summary.InviteSendRatePercent = guestConversionPercent(summary.InviteSentCount, summary.ApprovedStageCount)
	summary.InviteCompletionRatePercent = guestConversionPercent(summary.CompletedAfterInviteCount, summary.InviteSentCount)
	summary.EndToEndCompletionRatePercent = guestConversionPercent(summary.CompletedStageCount, summary.TotalRecords)
	if submitToApprovalSamples > 0 {
		summary.AvgSubmitToApprovalMinutes = submitToApprovalTotal / submitToApprovalSamples
	}
	if submitToInviteSamples > 0 {
		summary.AvgSubmitToInviteMinutes = submitToInviteTotal / submitToInviteSamples
	}
	if submitToCompletionSamples > 0 {
		summary.AvgSubmitToCompletionMinutes = submitToCompletionTotal / submitToCompletionSamples
	}
	summary.Roles = sessionAnalyticsCounts(roleCounts)
	summary.Sponsors = sessionAnalyticsCounts(sponsorCounts)
	summary.Companies = sessionAnalyticsCounts(companyCounts)
	summary.Buckets = buckets

	return summary, nil
}

func guestConversionPercent(numerator, denominator int) int {
	if numerator <= 0 || denominator <= 0 {
		return 0
	}
	return int((numerator*100 + denominator/2) / denominator)
}
