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

func HandleGetGuestConversionAnalytics(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestConversionAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, guestConversionAnalyticsPayload(query, summary))
}

func HandleExportGuestConversionAnalytics(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestConversionAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	filenamePrefix := "aegisnas-guest-conversion-analytics"
	if query.Status != "" {
		filenamePrefix += "-" + sanitizeDownloadName(query.Status)
	}
	filenamePrefix += fmt.Sprintf("-%dh", summary.WindowHours)

	switch format {
	case "", "csv":
		payload, err := guestConversionAnalyticsCSV(summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(guestConversionAnalyticsPayload(query, summary))
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
	audit(r, "download_guest_conversion_analytics", filenamePrefix, "downloaded")
}

func guestConversionAnalyticsPayload(query db.GuestLifecycleQuery, summary db.GuestConversionSummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"status":       query.Status,
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"summary":      summary,
	}
}

func guestConversionAnalyticsCSV(summary db.GuestConversionSummary) ([]byte, error) {
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
		{"open_pending_count", int64(summary.OpenPendingCount)},
		{"sponsor_approval_required_count", int64(summary.SponsorApprovalRequiredCount)},
		{"approved_stage_count", int64(summary.ApprovedStageCount)},
		{"rejected_stage_count", int64(summary.RejectedStageCount)},
		{"invite_queued_count", int64(summary.InviteQueuedCount)},
		{"invite_sent_count", int64(summary.InviteSentCount)},
		{"invite_failed_count", int64(summary.InviteFailedCount)},
		{"completed_stage_count", int64(summary.CompletedStageCount)},
		{"approved_without_successful_invite_count", int64(summary.ApprovedWithoutSuccessfulInviteCount)},
		{"invited_not_completed_count", int64(summary.InvitedNotCompletedCount)},
		{"completed_after_invite_count", int64(summary.CompletedAfterInviteCount)},
		{"unique_guests_window", int64(summary.UniqueGuestsWindow)},
		{"unique_sponsors_window", int64(summary.UniqueSponsorsWindow)},
		{"unique_companies_window", int64(summary.UniqueCompaniesWindow)},
		{"approval_rate_percent", int64(summary.ApprovalRatePercent)},
		{"invite_send_rate_percent", int64(summary.InviteSendRatePercent)},
		{"invite_completion_rate_percent", int64(summary.InviteCompletionRatePercent)},
		{"end_to_end_completion_rate_percent", int64(summary.EndToEndCompletionRatePercent)},
		{"avg_submit_to_approval_minutes", summary.AvgSubmitToApprovalMinutes},
		{"max_submit_to_approval_minutes", summary.MaxSubmitToApprovalMinutes},
		{"avg_submit_to_invite_minutes", summary.AvgSubmitToInviteMinutes},
		{"max_submit_to_invite_minutes", summary.MaxSubmitToInviteMinutes},
		{"avg_submit_to_completion_minutes", summary.AvgSubmitToCompletionMinutes},
		{"max_submit_to_completion_minutes", summary.MaxSubmitToCompletionMinutes},
	}
	for _, row := range summaryRows {
		if err := writer.Write([]string{"summary", row.Name, "", "", fmt.Sprint(row.Count)}); err != nil {
			return nil, err
		}
	}

	for _, item := range summary.Roles {
		if err := writer.Write([]string{"role", item.Name, "", "", fmt.Sprint(item.Count)}); err != nil {
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
	for _, bucket := range summary.Buckets {
		rows := []struct {
			Name  string
			Count int
		}{
			{"submitted_count", bucket.SubmittedCount},
			{"approved_count", bucket.ApprovedCount},
			{"rejected_count", bucket.RejectedCount},
			{"invite_sent_count", bucket.InviteSentCount},
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
