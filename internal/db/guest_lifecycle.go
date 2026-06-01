package db

import (
	"fmt"
	"strings"
	"time"
)

const (
	defaultGuestLifecycleWindow      = 24 * time.Hour
	defaultGuestLifecycleBucketCount = 24
	maxGuestLifecycleBucketCount     = 96
)

type GuestLifecycleQuery struct {
	Status       string
	TenantScopes []string
	Window       time.Duration
	BucketCount  int
	Limit        int
}

type GuestLifecycleSummary struct {
	WindowHours                  int                     `json:"window_hours"`
	BucketCount                  int                     `json:"bucket_count"`
	BucketMinutes                int                     `json:"bucket_minutes"`
	TotalRecords                 int                     `json:"total_records"`
	PendingCount                 int                     `json:"pending_count"`
	ApprovedCount                int                     `json:"approved_count"`
	RejectedCount                int                     `json:"rejected_count"`
	CompletedCount               int                     `json:"completed_count"`
	SponsorApprovalRequiredCount int                     `json:"sponsor_approval_required_count"`
	ApprovalDeliveryPendingCount int                     `json:"approval_delivery_pending_count"`
	ApprovalDeliverySentCount    int                     `json:"approval_delivery_sent_count"`
	ApprovalDeliveryFailedCount  int                     `json:"approval_delivery_failed_count"`
	InviteQueuedCount            int                     `json:"invite_queued_count"`
	InviteSentCount              int                     `json:"invite_sent_count"`
	InviteFailedCount            int                     `json:"invite_failed_count"`
	UniqueGuestsWindow           int                     `json:"unique_guests_window"`
	UniqueSponsorsWindow         int                     `json:"unique_sponsors_window"`
	UniqueCompaniesWindow        int                     `json:"unique_companies_window"`
	AvgApprovalMinutes           int64                   `json:"avg_approval_minutes"`
	AvgCompletionMinutes         int64                   `json:"avg_completion_minutes"`
	LatestSubmittedAt            string                  `json:"latest_submitted_at"`
	LatestApprovedAt             string                  `json:"latest_approved_at"`
	LatestRejectedAt             string                  `json:"latest_rejected_at"`
	LatestCompletedAt            string                  `json:"latest_completed_at"`
	Roles                        []SessionAnalyticsCount `json:"roles"`
	Buckets                      []GuestLifecycleBucket  `json:"buckets"`
}

type GuestLifecycleBucket struct {
	Start          string `json:"start"`
	End            string `json:"end"`
	SubmittedCount int    `json:"submitted_count"`
	ApprovedCount  int    `json:"approved_count"`
	RejectedCount  int    `json:"rejected_count"`
	CompletedCount int    `json:"completed_count"`
}

type guestLifecycleRow struct {
	Status                 string
	Tenant                 string
	FullName               string
	Email                  string
	Phone                  string
	Company                string
	SponsorName            string
	SponsorEmail           string
	SponsorPhone           string
	Role                   string
	ApprovalDeliveryStatus string
	ApprovalDeliveryError  string
	InviteDeliveryStatus   string
	InviteDeliveryError    string
	CreatedAt              string
	UpdatedAt              string
	ApprovedAt             string
	RejectedAt             string
	CompletedAt            string
}

var guestLifecycleNow = time.Now

func GetGuestLifecycleSummary(query GuestLifecycleQuery) (GuestLifecycleSummary, error) {
	if DB == nil {
		return GuestLifecycleSummary{}, fmt.Errorf("database not initialized")
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
		return GuestLifecycleSummary{}, err
	}

	buckets := make([]GuestLifecycleBucket, bucketCount)
	for i := range buckets {
		start := cutoff.Add(time.Duration(i) * bucketDuration)
		end := start.Add(bucketDuration)
		if i == bucketCount-1 {
			end = now
		}
		buckets[i] = GuestLifecycleBucket{
			Start: start.Format(time.RFC3339),
			End:   end.Format(time.RFC3339),
		}
	}

	summary := GuestLifecycleSummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketDuration.Minutes()),
		Buckets:       buckets,
	}

	roleCounts := map[string]int{}
	guestSet := map[string]struct{}{}
	sponsorSet := map[string]struct{}{}
	companySet := map[string]struct{}{}
	var approvalMinutesTotal int64
	var approvalCount int64
	var completionMinutesTotal int64
	var completionCount int64

	for _, item := range rows {
		summary.TotalRecords++

		switch strings.ToLower(strings.TrimSpace(item.Status)) {
		case "pending":
			summary.PendingCount++
		case "approved":
			summary.ApprovedCount++
		case "rejected":
			summary.RejectedCount++
		case "completed":
			summary.CompletedCount++
		}

		switch strings.ToLower(strings.TrimSpace(item.ApprovalDeliveryStatus)) {
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

		switch strings.ToLower(strings.TrimSpace(item.InviteDeliveryStatus)) {
		case "queued":
			summary.InviteQueuedCount++
		case "sent":
			summary.InviteSentCount++
		case "failed":
			summary.InviteFailedCount++
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

		if !createdAt.IsZero() {
			createdText := createdAt.Format(time.RFC3339)
			if summary.LatestSubmittedAt == "" || createdText > summary.LatestSubmittedAt {
				summary.LatestSubmittedAt = createdText
			}
			if !createdAt.Before(cutoff) {
				buckets[bucketIndex(createdAt, cutoff, bucketDuration, bucketCount)].SubmittedCount++
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
				approvalMinutesTotal += int64(approvedAt.Sub(createdAt).Minutes())
				approvalCount++
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

		if !completedAt.IsZero() {
			completedText := completedAt.Format(time.RFC3339)
			if summary.LatestCompletedAt == "" || completedText > summary.LatestCompletedAt {
				summary.LatestCompletedAt = completedText
			}
			if !completedAt.Before(cutoff) {
				buckets[bucketIndex(completedAt, cutoff, bucketDuration, bucketCount)].CompletedCount++
			}
			if !createdAt.IsZero() && completedAt.After(createdAt) {
				completionMinutesTotal += int64(completedAt.Sub(createdAt).Minutes())
				completionCount++
			}
		}
	}

	summary.UniqueGuestsWindow = len(guestSet)
	summary.UniqueSponsorsWindow = len(sponsorSet)
	summary.UniqueCompaniesWindow = len(companySet)
	if approvalCount > 0 {
		summary.AvgApprovalMinutes = approvalMinutesTotal / approvalCount
	}
	if completionCount > 0 {
		summary.AvgCompletionMinutes = completionMinutesTotal / completionCount
	}
	summary.Roles = sessionAnalyticsCounts(roleCounts)
	summary.Buckets = buckets

	return summary, nil
}

func listGuestLifecycleRows(query GuestLifecycleQuery) ([]guestLifecycleRow, error) {
	baseQuery := `SELECT
		COALESCE(status, ''),
		COALESCE(tenant, ''),
		COALESCE(full_name, ''),
		COALESCE(email, ''),
		COALESCE(phone, ''),
		COALESCE(company, ''),
		COALESCE(sponsor_name, ''),
		COALESCE(sponsor_email, ''),
		COALESCE(sponsor_phone, ''),
		COALESCE(role, ''),
		COALESCE(approval_delivery_status, ''),
		COALESCE(approval_delivery_error, ''),
		COALESCE(invite_delivery_status, ''),
		COALESCE(invite_delivery_error, ''),
		COALESCE(CAST(created_at AS TEXT), ''),
		COALESCE(CAST(updated_at AS TEXT), ''),
		COALESCE(CAST(approved_at AS TEXT), ''),
		COALESCE(CAST(rejected_at AS TEXT), ''),
		COALESCE(CAST(completed_at AS TEXT), '')
		FROM guest_registrations`
	clauses, args := guestLifecycleClauses(query)
	if len(clauses) > 0 {
		baseQuery += ` WHERE ` + strings.Join(clauses, " AND ")
	}
	baseQuery += ` ORDER BY datetime(created_at) DESC, id DESC`

	rows, err := DB.Query(baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("list guest lifecycle rows: %w", err)
	}
	defer rows.Close()

	items := []guestLifecycleRow{}
	for rows.Next() {
		var item guestLifecycleRow
		if err := rows.Scan(
			&item.Status,
			&item.Tenant,
			&item.FullName,
			&item.Email,
			&item.Phone,
			&item.Company,
			&item.SponsorName,
			&item.SponsorEmail,
			&item.SponsorPhone,
			&item.Role,
			&item.ApprovalDeliveryStatus,
			&item.ApprovalDeliveryError,
			&item.InviteDeliveryStatus,
			&item.InviteDeliveryError,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.ApprovedAt,
			&item.RejectedAt,
			&item.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("scan guest lifecycle row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate guest lifecycle rows: %w", err)
	}
	return items, nil
}

func guestLifecycleClauses(query GuestLifecycleQuery) ([]string, []any) {
	clauses := []string{}
	args := []any{}

	if status := strings.ToLower(strings.TrimSpace(query.Status)); status != "" {
		clauses = append(clauses, "LOWER(COALESCE(status, '')) = ?")
		args = append(args, status)
	}
	if scopes := normalizeGuestLifecycleScopes(query.TenantScopes); len(scopes) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(scopes)), ",")
		clauses = append(clauses, fmt.Sprintf("COALESCE(tenant, '') IN (%s)", placeholders))
		for _, scope := range scopes {
			args = append(args, scope)
		}
	}
	return clauses, args
}

func normalizeGuestLifecycleScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(scopes))
	seen := map[string]struct{}{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func guestLifecycleGuestKey(item guestLifecycleRow) string {
	for _, value := range []string{item.Email, item.Phone, item.FullName} {
		value = strings.TrimSpace(value)
		if value != "" {
			return strings.ToLower(value)
		}
	}
	return strings.ToLower(strings.TrimSpace(item.Tenant)) + "::anonymous"
}

func guestLifecycleSponsorKey(item guestLifecycleRow) string {
	for _, value := range []string{item.SponsorEmail, item.SponsorPhone, item.SponsorName} {
		value = strings.TrimSpace(value)
		if value != "" {
			return strings.ToLower(value)
		}
	}
	return ""
}
