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

func HandleGetGuestInviteAnalytics(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestInviteAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, guestInviteAnalyticsPayload(query, summary))
}

func HandleExportGuestInviteAnalytics(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestInviteAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	filenamePrefix := "aegisnas-guest-invite-analytics"
	if query.Status != "" {
		filenamePrefix += "-" + sanitizeDownloadName(query.Status)
	}
	filenamePrefix += fmt.Sprintf("-%dh", summary.WindowHours)

	switch format {
	case "", "csv":
		payload, err := guestInviteAnalyticsCSV(summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(guestInviteAnalyticsPayload(query, summary))
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

func guestInviteAnalyticsPayload(query db.GuestLifecycleQuery, summary db.GuestInviteAnalyticsSummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"status":       query.Status,
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"summary":      summary,
	}
}

func guestInviteAnalyticsCSV(summary db.GuestInviteAnalyticsSummary) ([]byte, error) {
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
		{"tracked_invite_records_count", int64(summary.TrackedInviteRecordsCount)},
		{"invite_queued_count", int64(summary.InviteQueuedCount)},
		{"invite_sent_count", int64(summary.InviteSentCount)},
		{"invite_failed_count", int64(summary.InviteFailedCount)},
		{"invite_not_requested_count", int64(summary.InviteNotRequestedCount)},
		{"completed_after_invite_count", int64(summary.CompletedAfterInviteCount)},
		{"unique_guests_window", int64(summary.UniqueGuestsWindow)},
		{"unique_sponsors_window", int64(summary.UniqueSponsorsWindow)},
		{"unique_companies_window", int64(summary.UniqueCompaniesWindow)},
		{"avg_approval_to_invite_minutes", summary.AvgApprovalToInviteMinutes},
		{"max_approval_to_invite_minutes", summary.MaxApprovalToInviteMinutes},
		{"avg_invite_to_completion_minutes", summary.AvgInviteToCompletionMinutes},
		{"max_invite_to_completion_minutes", summary.MaxInviteToCompletionMinutes},
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
	for _, item := range summary.InviteDeliveryStatuses {
		if err := writer.Write([]string{"invite_status", item.Name, "", "", fmt.Sprint(item.Count)}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.InviteFailureReasons {
		if err := writer.Write([]string{"invite_failure_reason", item.Name, "", "", fmt.Sprint(item.Count)}); err != nil {
			return nil, err
		}
	}
	for _, bucket := range summary.Buckets {
		rows := []struct {
			Name  string
			Count int
		}{
			{"invite_queued_count", bucket.InviteQueuedCount},
			{"invite_sent_count", bucket.InviteSentCount},
			{"invite_failed_count", bucket.InviteFailedCount},
			{"completed_after_invite_count", bucket.CompletedAfterInviteCount},
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
