package adminapi

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func HandleGetGuestDeliveryAnalytics(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestDeliveryAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, guestDeliveryAnalyticsPayload(query, summary))
}

func HandleExportGuestDeliveryAnalytics(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestDeliveryAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	filenamePrefix := "aegisnas-guest-delivery-analytics"
	if query.Status != "" {
		filenamePrefix += "-" + sanitizeDownloadName(query.Status)
	}
	filenamePrefix += fmt.Sprintf("-%dh", summary.WindowHours)

	switch format {
	case "", "csv":
		payload, err := guestDeliveryAnalyticsCSV(summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(guestDeliveryAnalyticsPayload(query, summary))
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
	}
}

func guestDeliveryAnalyticsPayload(query db.GuestLifecycleQuery, summary db.GuestDeliveryAnalyticsSummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"status":       query.Status,
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"summary":      summary,
	}
}

func guestDeliveryAnalyticsCSV(summary db.GuestDeliveryAnalyticsSummary) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"section", "name", "bucket_start", "bucket_end", "count"}); err != nil {
		return nil, err
	}

	summaryRows := []struct {
		Name  string
		Count int64
	}{
		{"window_hours", int64(summary.WindowHours)},
		{"bucket_count", int64(summary.BucketCount)},
		{"bucket_minutes", int64(summary.BucketMinutes)},
		{"total_records", int64(summary.TotalRecords)},
		{"sponsor_approval_required_count", int64(summary.SponsorApprovalRequiredCount)},
		{"pending_sponsor_approval_count", int64(summary.PendingSponsorApprovalCount)},
		{"pending_invite_queue_count", int64(summary.PendingInviteQueueCount)},
		{"approval_delivery_pending_count", int64(summary.ApprovalDeliveryPendingCount)},
		{"approval_delivery_sent_count", int64(summary.ApprovalDeliverySentCount)},
		{"approval_delivery_failed_count", int64(summary.ApprovalDeliveryFailedCount)},
		{"invite_queued_count", int64(summary.InviteQueuedCount)},
		{"invite_sent_count", int64(summary.InviteSentCount)},
		{"invite_failed_count", int64(summary.InviteFailedCount)},
		{"approved_count", int64(summary.ApprovedCount)},
		{"rejected_count", int64(summary.RejectedCount)},
		{"completed_count", int64(summary.CompletedCount)},
		{"unique_guests_window", int64(summary.UniqueGuestsWindow)},
		{"unique_sponsors_window", int64(summary.UniqueSponsorsWindow)},
		{"unique_companies_window", int64(summary.UniqueCompaniesWindow)},
		{"avg_approval_minutes", summary.AvgApprovalMinutes},
		{"max_approval_minutes", summary.MaxApprovalMinutes},
		{"avg_approval_to_completion_minutes", summary.AvgApprovalToCompletionMinutes},
		{"max_approval_to_completion_minutes", summary.MaxApprovalToCompletionMinutes},
	}
	for _, row := range summaryRows {
		if err := writer.Write([]string{"summary", row.Name, "", "", fmt.Sprint(row.Count)}); err != nil {
			return nil, err
		}
	}

	for _, item := range summary.Sponsors {
		if err := writer.Write([]string{"sponsor", item.Name, "", "", fmt.Sprint(item.Count)}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.Companies {
		if err := writer.Write([]string{"company", item.Name, "", "", fmt.Sprint(item.Count)}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.Roles {
		if err := writer.Write([]string{"role", item.Name, "", "", fmt.Sprint(item.Count)}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.ApprovalDeliveryStatuses {
		if err := writer.Write([]string{"approval_status", item.Name, "", "", fmt.Sprint(item.Count)}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.InviteDeliveryStatuses {
		if err := writer.Write([]string{"invite_status", item.Name, "", "", fmt.Sprint(item.Count)}); err != nil {
			return nil, err
		}
	}
	for _, bucket := range summary.Buckets {
		rows := []struct {
			Name  string
			Count int
		}{
			{"submitted_count", bucket.SubmittedCount},
			{"pending_sponsor_approval_count", bucket.PendingSponsorApprovalCount},
			{"approval_delivery_failed_count", bucket.ApprovalDeliveryFailedCount},
			{"approved_count", bucket.ApprovedCount},
			{"rejected_count", bucket.RejectedCount},
			{"invite_queued_count", bucket.InviteQueuedCount},
			{"invite_sent_count", bucket.InviteSentCount},
			{"invite_failed_count", bucket.InviteFailedCount},
			{"completed_count", bucket.CompletedCount},
		}
		for _, row := range rows {
			if err := writer.Write([]string{"bucket", row.Name, bucket.Start, bucket.End, fmt.Sprint(row.Count)}); err != nil {
				return nil, err
			}
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
