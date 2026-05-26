package adminapi

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/portal/guestworkflow"
)

const (
	defaultGuestLifecycleWindowHours = 24
	defaultGuestLifecycleBucketCount = 24
)

func HandleGetGuestLifecycle(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, 200)
	records, err := loadGuestLifecycleRecords(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.GetGuestLifecycleSummary(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, guestLifecyclePayload(query, records, summary))
}

func HandleExportGuestLifecycle(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, 5000)
	records, err := loadGuestLifecycleRecords(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.GetGuestLifecycleSummary(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	filenamePrefix := "aegisnas-guest-lifecycle"
	if query.Status != "" {
		filenamePrefix += "-" + sanitizeDownloadName(query.Status)
	}
	filenamePrefix += fmt.Sprintf("-%dh", summary.WindowHours)

	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "", "csv":
		payload, err := guestLifecycleCSV(summary, records)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(guestLifecyclePayload(query, records, summary))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(append(payload, '\n'))
	default:
		http.Error(w, "unsupported export format", http.StatusBadRequest)
		return
	}
	audit(r, "download_guest_lifecycle", filenamePrefix, "downloaded")
}

func guestLifecycleQueryFromRequest(r *http.Request, fallbackLimit int) db.GuestLifecycleQuery {
	return db.GuestLifecycleQuery{
		Status:       strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status"))),
		TenantScopes: adminTenantScopesFromRequest(r),
		Window:       time.Duration(parsePositiveInt(r.URL.Query().Get("window_hours"), defaultGuestLifecycleWindowHours, 1, 168)) * time.Hour,
		BucketCount:  parsePositiveInt(r.URL.Query().Get("bucket_count"), defaultGuestLifecycleBucketCount, 1, 96),
		Limit:        parseSessionHistoryLimit(r.URL.Query().Get("limit"), fallbackLimit),
	}
}

func guestLifecyclePayload(query db.GuestLifecycleQuery, records []guestworkflow.Registration, summary db.GuestLifecycleSummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"status":       query.Status,
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"history":      records,
		"count":        len(records),
		"summary":      summary,
	}
}

func loadGuestLifecycleRecords(query db.GuestLifecycleQuery) ([]guestworkflow.Registration, error) {
	service := guestworkflow.New(config.Get(), nil, nil)
	return service.List(query.Status, query.Limit, query.TenantScopes...)
}

func guestLifecycleCSV(summary db.GuestLifecycleSummary, records []guestworkflow.Registration) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	header := []string{
		"section", "name", "start", "end", "count", "value",
		"id", "status", "full_name", "email", "phone", "company", "purpose",
		"sponsor_name", "sponsor_email", "sponsor_phone",
		"client_mac", "client_ip", "username", "role", "approved_by",
		"rejection_reason", "approval_delivery_status", "invite_delivery_status",
		"created_at", "updated_at", "approved_at", "rejected_at", "completed_at", "expires_at",
	}
	if err := writer.Write(header); err != nil {
		return nil, err
	}
	writeRow := func(values ...string) error {
		row := make([]string, len(header))
		copy(row, values)
		return writer.Write(row)
	}

	summaryRows := []struct {
		Name  string
		Value string
	}{
		{"window_hours", fmt.Sprint(summary.WindowHours)},
		{"bucket_count", fmt.Sprint(summary.BucketCount)},
		{"bucket_minutes", fmt.Sprint(summary.BucketMinutes)},
		{"total_records", fmt.Sprint(summary.TotalRecords)},
		{"pending_count", fmt.Sprint(summary.PendingCount)},
		{"approved_count", fmt.Sprint(summary.ApprovedCount)},
		{"rejected_count", fmt.Sprint(summary.RejectedCount)},
		{"completed_count", fmt.Sprint(summary.CompletedCount)},
		{"sponsor_approval_required_count", fmt.Sprint(summary.SponsorApprovalRequiredCount)},
		{"approval_delivery_pending_count", fmt.Sprint(summary.ApprovalDeliveryPendingCount)},
		{"approval_delivery_sent_count", fmt.Sprint(summary.ApprovalDeliverySentCount)},
		{"approval_delivery_failed_count", fmt.Sprint(summary.ApprovalDeliveryFailedCount)},
		{"invite_queued_count", fmt.Sprint(summary.InviteQueuedCount)},
		{"invite_sent_count", fmt.Sprint(summary.InviteSentCount)},
		{"invite_failed_count", fmt.Sprint(summary.InviteFailedCount)},
		{"unique_guests_window", fmt.Sprint(summary.UniqueGuestsWindow)},
		{"unique_sponsors_window", fmt.Sprint(summary.UniqueSponsorsWindow)},
		{"unique_companies_window", fmt.Sprint(summary.UniqueCompaniesWindow)},
		{"avg_approval_minutes", fmt.Sprint(summary.AvgApprovalMinutes)},
		{"avg_completion_minutes", fmt.Sprint(summary.AvgCompletionMinutes)},
		{"latest_submitted_at", summary.LatestSubmittedAt},
		{"latest_approved_at", summary.LatestApprovedAt},
		{"latest_rejected_at", summary.LatestRejectedAt},
		{"latest_completed_at", summary.LatestCompletedAt},
	}
	for _, row := range summaryRows {
		if err := writeRow("summary", row.Name, "", "", "", row.Value); err != nil {
			return nil, err
		}
	}

	for _, role := range summary.Roles {
		if err := writeRow("role", role.Name, "", "", fmt.Sprint(role.Count), ""); err != nil {
			return nil, err
		}
	}
	for _, bucket := range summary.Buckets {
		if err := writeRow("bucket", "submitted_count", bucket.Start, bucket.End, fmt.Sprint(bucket.SubmittedCount), ""); err != nil {
			return nil, err
		}
		if err := writeRow("bucket", "approved_count", bucket.Start, bucket.End, fmt.Sprint(bucket.ApprovedCount), ""); err != nil {
			return nil, err
		}
		if err := writeRow("bucket", "rejected_count", bucket.Start, bucket.End, fmt.Sprint(bucket.RejectedCount), ""); err != nil {
			return nil, err
		}
		if err := writeRow("bucket", "completed_count", bucket.Start, bucket.End, fmt.Sprint(bucket.CompletedCount), ""); err != nil {
			return nil, err
		}
	}
	for _, item := range records {
		if err := writeRow(
			"history", "", "", "", "", "",
			item.ID, item.Status, item.FullName, item.Email, item.Phone, item.Company, item.Purpose,
			item.SponsorName, item.SponsorEmail, item.SponsorPhone,
			item.ClientMAC, item.ClientIP, item.Username, item.Role, item.ApprovedBy,
			item.RejectionReason, item.ApprovalDeliveryStatus, item.InviteDeliveryStatus,
			item.CreatedAt, item.UpdatedAt, item.ApprovedAt, item.RejectedAt, item.CompletedAt, item.ExpiresAt,
		); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
