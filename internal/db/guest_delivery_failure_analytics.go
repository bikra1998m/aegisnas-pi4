package db

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type GuestDeliveryFailureAnalyticsSummary struct {
	WindowHours                  int                                   `json:"window_hours"`
	BucketCount                  int                                   `json:"bucket_count"`
	BucketMinutes                int                                   `json:"bucket_minutes"`
	TotalRecords                 int                                   `json:"total_records"`
	DeliveryIssueRecordsCount    int                                   `json:"delivery_issue_records_count"`
	ApprovalDeliveryFailedCount  int                                   `json:"approval_delivery_failed_count"`
	InviteFailedCount            int                                   `json:"invite_failed_count"`
	PendingInviteQueueCount      int                                   `json:"pending_invite_queue_count"`
	TotalFailureCount            int                                   `json:"total_failure_count"`
	UniqueSponsorsWindow         int                                   `json:"unique_sponsors_window"`
	UniqueCompaniesWindow        int                                   `json:"unique_companies_window"`
	AvgPendingInviteQueueMinutes int64                                 `json:"avg_pending_invite_queue_minutes"`
	MaxPendingInviteQueueMinutes int64                                 `json:"max_pending_invite_queue_minutes"`
	LatestApprovalFailureAt      string                                `json:"latest_approval_failure_at"`
	LatestInviteFailureAt        string                                `json:"latest_invite_failure_at"`
	LatestQueuedInviteAt         string                                `json:"latest_queued_invite_at"`
	ApprovalErrors               []SessionAnalyticsCount               `json:"approval_errors"`
	InviteErrors                 []SessionAnalyticsCount               `json:"invite_errors"`
	Sponsors                     []GuestDeliveryIssueCounterparty      `json:"sponsors"`
	Companies                    []GuestDeliveryIssueCounterparty      `json:"companies"`
	Buckets                      []GuestDeliveryFailureAnalyticsBucket `json:"buckets"`
}

type GuestDeliveryIssueCounterparty struct {
	Name                         string `json:"name"`
	DeliveryIssueRecordsCount    int    `json:"delivery_issue_records_count"`
	ApprovalDeliveryFailedCount  int    `json:"approval_delivery_failed_count"`
	InviteFailedCount            int    `json:"invite_failed_count"`
	PendingInviteQueueCount      int    `json:"pending_invite_queue_count"`
	TotalFailureCount            int    `json:"total_failure_count"`
	AvgPendingInviteQueueMinutes int64  `json:"avg_pending_invite_queue_minutes"`
	MaxPendingInviteQueueMinutes int64  `json:"max_pending_invite_queue_minutes"`
	LatestIssueAt                string `json:"latest_issue_at,omitempty"`
}

type GuestDeliveryFailureAnalyticsBucket struct {
	Start                       string `json:"start"`
	End                         string `json:"end"`
	ApprovalDeliveryFailedCount int    `json:"approval_delivery_failed_count"`
	InviteFailedCount           int    `json:"invite_failed_count"`
	PendingInviteQueueCount     int    `json:"pending_invite_queue_count"`
	TotalFailureCount           int    `json:"total_failure_count"`
}

type guestDeliveryIssueAccumulator struct {
	Name                         string
	DeliveryIssueRecordsCount    int
	ApprovalDeliveryFailedCount  int
	InviteFailedCount            int
	PendingInviteQueueCount      int
	TotalFailureCount            int
	PendingInviteQueueMinutesSum int64
	PendingInviteQueueSamples    int64
	MaxPendingInviteQueueMinutes int64
	LatestIssueAt                string
}

func GetGuestDeliveryFailureAnalytics(query GuestLifecycleQuery) (GuestDeliveryFailureAnalyticsSummary, error) {
	if DB == nil {
		return GuestDeliveryFailureAnalyticsSummary{}, fmt.Errorf("database not initialized")
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
		return GuestDeliveryFailureAnalyticsSummary{}, err
	}

	buckets := make([]GuestDeliveryFailureAnalyticsBucket, bucketCount)
	for i := range buckets {
		start := cutoff.Add(time.Duration(i) * bucketDuration)
		end := start.Add(bucketDuration)
		if i == bucketCount-1 {
			end = now
		}
		buckets[i] = GuestDeliveryFailureAnalyticsBucket{
			Start: start.Format(time.RFC3339),
			End:   end.Format(time.RFC3339),
		}
	}

	summary := GuestDeliveryFailureAnalyticsSummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketDuration.Minutes()),
		Buckets:       buckets,
	}

	approvalErrorCounts := map[string]int{}
	inviteErrorCounts := map[string]int{}
	sponsorStats := map[string]*guestDeliveryIssueAccumulator{}
	companyStats := map[string]*guestDeliveryIssueAccumulator{}
	sponsorSet := map[string]struct{}{}
	companySet := map[string]struct{}{}
	var pendingInviteQueueMinutesTotal int64
	var pendingInviteQueueSamples int64

	for _, item := range rows {
		summary.TotalRecords++

		createdAt := parseSessionAnalyticsTime(item.CreatedAt)
		updatedAt := parseSessionAnalyticsTime(item.UpdatedAt)
		approvedAt := parseSessionAnalyticsTime(item.ApprovedAt)
		approvalStatusName := guestDeliveryStatusName(item.ApprovalDeliveryStatus, "unknown")
		inviteStatusName := guestDeliveryStatusName(item.InviteDeliveryStatus, "unknown")
		sponsorName := guestDeliverySponsorLabel(item)
		companyName := strings.TrimSpace(item.Company)
		sponsorActor := guestDeliveryIssueAccumulatorForName(sponsorStats, sponsorName)
		companyActor := guestDeliveryIssueAccumulatorForName(companyStats, companyName)

		issueRecord := false
		latestIssueAt := ""

		if approvalStatusName == "failed" {
			issueRecord = true
			summary.ApprovalDeliveryFailedCount++
			summary.TotalFailureCount++
			errorName := guestDeliveryFailureErrorName(item.ApprovalDeliveryError)
			approvalErrorCounts[errorName]++

			approvalFailureAt := guestDeliveryFailureEventTime(updatedAt, createdAt)
			failureText := guestDeliveryIssueTimeText(approvalFailureAt)
			summary.LatestApprovalFailureAt = guestDeliveryLatestTimestamp(summary.LatestApprovalFailureAt, failureText)
			latestIssueAt = guestDeliveryLatestTimestamp(latestIssueAt, failureText)
			if !approvalFailureAt.IsZero() && !approvalFailureAt.Before(cutoff) {
				idx := bucketIndex(approvalFailureAt, cutoff, bucketDuration, bucketCount)
				buckets[idx].ApprovalDeliveryFailedCount++
				buckets[idx].TotalFailureCount++
				if sponsorName != "" {
					sponsorSet[strings.ToLower(sponsorName)] = struct{}{}
				}
				if companyName != "" {
					companySet[strings.ToLower(companyName)] = struct{}{}
				}
			}
			if sponsorActor != nil {
				sponsorActor.ApprovalDeliveryFailedCount++
				sponsorActor.TotalFailureCount++
			}
			if companyActor != nil {
				companyActor.ApprovalDeliveryFailedCount++
				companyActor.TotalFailureCount++
			}
		}

		if inviteStatusName == "failed" {
			issueRecord = true
			summary.InviteFailedCount++
			summary.TotalFailureCount++
			errorName := guestDeliveryFailureErrorName(item.InviteDeliveryError)
			inviteErrorCounts[errorName]++

			inviteFailureAt := guestDeliveryFailureEventTime(updatedAt, guestDeliveryInviteAnchor(createdAt, approvedAt))
			failureText := guestDeliveryIssueTimeText(inviteFailureAt)
			summary.LatestInviteFailureAt = guestDeliveryLatestTimestamp(summary.LatestInviteFailureAt, failureText)
			latestIssueAt = guestDeliveryLatestTimestamp(latestIssueAt, failureText)
			if !inviteFailureAt.IsZero() && !inviteFailureAt.Before(cutoff) {
				idx := bucketIndex(inviteFailureAt, cutoff, bucketDuration, bucketCount)
				buckets[idx].InviteFailedCount++
				buckets[idx].TotalFailureCount++
				if sponsorName != "" {
					sponsorSet[strings.ToLower(sponsorName)] = struct{}{}
				}
				if companyName != "" {
					companySet[strings.ToLower(companyName)] = struct{}{}
				}
			}
			if sponsorActor != nil {
				sponsorActor.InviteFailedCount++
				sponsorActor.TotalFailureCount++
			}
			if companyActor != nil {
				companyActor.InviteFailedCount++
				companyActor.TotalFailureCount++
			}
		}

		if inviteStatusName == "queued" {
			issueRecord = true
			summary.PendingInviteQueueCount++
			inviteQueuedAt := guestDeliveryInviteAnchor(createdAt, approvedAt)
			queuedText := guestDeliveryIssueTimeText(inviteQueuedAt)
			summary.LatestQueuedInviteAt = guestDeliveryLatestTimestamp(summary.LatestQueuedInviteAt, queuedText)
			latestIssueAt = guestDeliveryLatestTimestamp(latestIssueAt, queuedText)
			if !inviteQueuedAt.IsZero() {
				queueMinutes := int64(now.Sub(inviteQueuedAt).Minutes())
				if queueMinutes < 0 {
					queueMinutes = 0
				}
				pendingInviteQueueMinutesTotal += queueMinutes
				pendingInviteQueueSamples++
				if queueMinutes > summary.MaxPendingInviteQueueMinutes {
					summary.MaxPendingInviteQueueMinutes = queueMinutes
				}
				if sponsorActor != nil {
					sponsorActor.PendingInviteQueueCount++
					sponsorActor.PendingInviteQueueMinutesSum += queueMinutes
					sponsorActor.PendingInviteQueueSamples++
					if queueMinutes > sponsorActor.MaxPendingInviteQueueMinutes {
						sponsorActor.MaxPendingInviteQueueMinutes = queueMinutes
					}
				}
				if companyActor != nil {
					companyActor.PendingInviteQueueCount++
					companyActor.PendingInviteQueueMinutesSum += queueMinutes
					companyActor.PendingInviteQueueSamples++
					if queueMinutes > companyActor.MaxPendingInviteQueueMinutes {
						companyActor.MaxPendingInviteQueueMinutes = queueMinutes
					}
				}
			} else {
				if sponsorActor != nil {
					sponsorActor.PendingInviteQueueCount++
				}
				if companyActor != nil {
					companyActor.PendingInviteQueueCount++
				}
			}
			if !inviteQueuedAt.IsZero() && !inviteQueuedAt.Before(cutoff) {
				idx := bucketIndex(inviteQueuedAt, cutoff, bucketDuration, bucketCount)
				buckets[idx].PendingInviteQueueCount++
				if sponsorName != "" {
					sponsorSet[strings.ToLower(sponsorName)] = struct{}{}
				}
				if companyName != "" {
					companySet[strings.ToLower(companyName)] = struct{}{}
				}
			}
		}

		if issueRecord {
			summary.DeliveryIssueRecordsCount++
			if sponsorActor != nil {
				sponsorActor.DeliveryIssueRecordsCount++
				sponsorActor.LatestIssueAt = guestDeliveryLatestTimestamp(sponsorActor.LatestIssueAt, latestIssueAt)
			}
			if companyActor != nil {
				companyActor.DeliveryIssueRecordsCount++
				companyActor.LatestIssueAt = guestDeliveryLatestTimestamp(companyActor.LatestIssueAt, latestIssueAt)
			}
		}
	}

	summary.UniqueSponsorsWindow = len(sponsorSet)
	summary.UniqueCompaniesWindow = len(companySet)
	if pendingInviteQueueSamples > 0 {
		summary.AvgPendingInviteQueueMinutes = pendingInviteQueueMinutesTotal / pendingInviteQueueSamples
	}
	summary.ApprovalErrors = sessionAnalyticsCounts(approvalErrorCounts)
	summary.InviteErrors = sessionAnalyticsCounts(inviteErrorCounts)
	summary.Sponsors = guestDeliveryIssueAccumulatorsToSlice(sponsorStats)
	summary.Companies = guestDeliveryIssueAccumulatorsToSlice(companyStats)
	summary.Buckets = buckets

	return summary, nil
}

func guestDeliveryIssueAccumulatorForName(items map[string]*guestDeliveryIssueAccumulator, name string) *guestDeliveryIssueAccumulator {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if existing, ok := items[name]; ok {
		return existing
	}
	item := &guestDeliveryIssueAccumulator{Name: name}
	items[name] = item
	return item
}

func guestDeliveryFailureErrorName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unspecified"
	}
	return value
}

func guestDeliveryFailureEventTime(updatedAt, fallback time.Time) time.Time {
	if !updatedAt.IsZero() {
		return updatedAt
	}
	return fallback
}

func guestDeliveryIssueTimeText(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func guestDeliveryLatestTimestamp(current, candidate string) string {
	if candidate == "" {
		return current
	}
	if current == "" || candidate > current {
		return candidate
	}
	return current
}

func guestDeliveryIssueAccumulatorsToSlice(items map[string]*guestDeliveryIssueAccumulator) []GuestDeliveryIssueCounterparty {
	if len(items) == 0 {
		return nil
	}
	out := make([]GuestDeliveryIssueCounterparty, 0, len(items))
	for _, item := range items {
		avgQueue := int64(0)
		if item.PendingInviteQueueSamples > 0 {
			avgQueue = item.PendingInviteQueueMinutesSum / item.PendingInviteQueueSamples
		}
		out = append(out, GuestDeliveryIssueCounterparty{
			Name:                         item.Name,
			DeliveryIssueRecordsCount:    item.DeliveryIssueRecordsCount,
			ApprovalDeliveryFailedCount:  item.ApprovalDeliveryFailedCount,
			InviteFailedCount:            item.InviteFailedCount,
			PendingInviteQueueCount:      item.PendingInviteQueueCount,
			TotalFailureCount:            item.TotalFailureCount,
			AvgPendingInviteQueueMinutes: avgQueue,
			MaxPendingInviteQueueMinutes: item.MaxPendingInviteQueueMinutes,
			LatestIssueAt:                item.LatestIssueAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TotalFailureCount != out[j].TotalFailureCount {
			return out[i].TotalFailureCount > out[j].TotalFailureCount
		}
		if out[i].PendingInviteQueueCount != out[j].PendingInviteQueueCount {
			return out[i].PendingInviteQueueCount > out[j].PendingInviteQueueCount
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}
