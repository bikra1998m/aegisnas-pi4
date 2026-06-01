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

func HandleGetGuestDeliveryFailures(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestDeliveryFailureAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, guestDeliveryFailuresPayload(query, summary))
}

func HandleExportGuestDeliveryFailures(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestDeliveryFailureAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	filenamePrefix := "aegisnas-guest-delivery-failures"
	if query.Status != "" {
		filenamePrefix += "-" + sanitizeDownloadName(query.Status)
	}
	filenamePrefix += fmt.Sprintf("-%dh", summary.WindowHours)

	switch format {
	case "", "csv":
		payload, err := guestDeliveryFailuresCSV(summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(guestDeliveryFailuresPayload(query, summary))
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
	audit(r, "download_guest_delivery_failures", filenamePrefix, "downloaded")
}

func guestDeliveryFailuresPayload(query db.GuestLifecycleQuery, summary db.GuestDeliveryFailureAnalyticsSummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"status":       query.Status,
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"summary":      summary,
	}
}

func guestDeliveryFailuresCSV(summary db.GuestDeliveryFailureAnalyticsSummary) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"section", "name", "bucket_start", "bucket_end", "count", "value"}); err != nil {
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
		{"delivery_issue_records_count", int64(summary.DeliveryIssueRecordsCount)},
		{"approval_delivery_failed_count", int64(summary.ApprovalDeliveryFailedCount)},
		{"invite_failed_count", int64(summary.InviteFailedCount)},
		{"pending_invite_queue_count", int64(summary.PendingInviteQueueCount)},
		{"total_failure_count", int64(summary.TotalFailureCount)},
		{"unique_sponsors_window", int64(summary.UniqueSponsorsWindow)},
		{"unique_companies_window", int64(summary.UniqueCompaniesWindow)},
		{"avg_pending_invite_queue_minutes", summary.AvgPendingInviteQueueMinutes},
		{"max_pending_invite_queue_minutes", summary.MaxPendingInviteQueueMinutes},
	}
	for _, row := range summaryRows {
		if err := writer.Write([]string{"summary", row.Name, "", "", fmt.Sprint(row.Count), ""}); err != nil {
			return nil, err
		}
	}

	for _, item := range summary.ApprovalErrors {
		if err := writer.Write([]string{"approval_error", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.InviteErrors {
		if err := writer.Write([]string{"invite_error", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.Sponsors {
		rows := []struct {
			Name  string
			Count int64
		}{
			{"delivery_issue_records_count", int64(item.DeliveryIssueRecordsCount)},
			{"approval_delivery_failed_count", int64(item.ApprovalDeliveryFailedCount)},
			{"invite_failed_count", int64(item.InviteFailedCount)},
			{"pending_invite_queue_count", int64(item.PendingInviteQueueCount)},
			{"total_failure_count", int64(item.TotalFailureCount)},
			{"avg_pending_invite_queue_minutes", item.AvgPendingInviteQueueMinutes},
			{"max_pending_invite_queue_minutes", item.MaxPendingInviteQueueMinutes},
		}
		for _, row := range rows {
			if err := writer.Write([]string{"sponsor", row.Name, "", "", fmt.Sprint(row.Count), item.Name}); err != nil {
				return nil, err
			}
		}
	}
	for _, item := range summary.Companies {
		rows := []struct {
			Name  string
			Count int64
		}{
			{"delivery_issue_records_count", int64(item.DeliveryIssueRecordsCount)},
			{"approval_delivery_failed_count", int64(item.ApprovalDeliveryFailedCount)},
			{"invite_failed_count", int64(item.InviteFailedCount)},
			{"pending_invite_queue_count", int64(item.PendingInviteQueueCount)},
			{"total_failure_count", int64(item.TotalFailureCount)},
		}
		for _, row := range rows {
			if err := writer.Write([]string{"company", row.Name, "", "", fmt.Sprint(row.Count), item.Name}); err != nil {
				return nil, err
			}
		}
	}
	for _, bucket := range summary.Buckets {
		rows := []struct {
			Name  string
			Count int
		}{
			{"approval_delivery_failed_count", bucket.ApprovalDeliveryFailedCount},
			{"invite_failed_count", bucket.InviteFailedCount},
			{"pending_invite_queue_count", bucket.PendingInviteQueueCount},
			{"total_failure_count", bucket.TotalFailureCount},
		}
		for _, row := range rows {
			if err := writer.Write([]string{"bucket", row.Name, bucket.Start, bucket.End, fmt.Sprint(row.Count), ""}); err != nil {
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
