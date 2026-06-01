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

func HandleGetGuestSponsorAnalytics(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestSponsorApprovalAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, guestSponsorAnalyticsPayload(query, summary))
}

func HandleExportGuestSponsorAnalytics(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestSponsorApprovalAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	filenamePrefix := "aegisnas-guest-sponsor-analytics"
	if query.Status != "" {
		filenamePrefix += "-" + sanitizeDownloadName(query.Status)
	}
	filenamePrefix += fmt.Sprintf("-%dh", summary.WindowHours)

	switch format {
	case "", "csv":
		payload, err := guestSponsorAnalyticsCSV(summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(guestSponsorAnalyticsPayload(query, summary))
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
	audit(r, "download_guest_sponsor_analytics", filenamePrefix, "downloaded")
}

func guestSponsorAnalyticsPayload(query db.GuestLifecycleQuery, summary db.GuestSponsorApprovalSummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"status":       query.Status,
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"summary":      summary,
	}
}

func guestSponsorAnalyticsCSV(summary db.GuestSponsorApprovalSummary) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"section", "name", "bucket_start", "bucket_end", "count", "value"}); err != nil {
		return nil, err
	}

	summaryRows := []struct {
		Name  string
		Value int64
	}{
		{"window_hours", int64(summary.WindowHours)},
		{"bucket_count", int64(summary.BucketCount)},
		{"bucket_minutes", int64(summary.BucketMinutes)},
		{"total_records", int64(summary.TotalRecords)},
		{"sponsor_approval_required_count", int64(summary.SponsorApprovalRequiredCount)},
		{"pending_sponsor_approval_count", int64(summary.PendingSponsorApprovalCount)},
		{"pending_older_than_30_minutes_count", int64(summary.PendingOlderThan30MinutesCount)},
		{"pending_older_than_4_hours_count", int64(summary.PendingOlderThan4HoursCount)},
		{"pending_older_than_24_hours_count", int64(summary.PendingOlderThan24HoursCount)},
		{"approved_with_sponsor_count", int64(summary.ApprovedWithSponsorCount)},
		{"rejected_with_sponsor_count", int64(summary.RejectedWithSponsorCount)},
		{"completed_with_sponsor_count", int64(summary.CompletedWithSponsorCount)},
		{"unique_sponsors_window", int64(summary.UniqueSponsorsWindow)},
		{"unique_companies_window", int64(summary.UniqueCompaniesWindow)},
		{"avg_approval_minutes", summary.AvgApprovalMinutes},
		{"max_approval_minutes", summary.MaxApprovalMinutes},
		{"avg_pending_approval_minutes", summary.AvgPendingApprovalMinutes},
		{"max_pending_approval_minutes", summary.MaxPendingApprovalMinutes},
	}
	for _, row := range summaryRows {
		if err := writer.Write([]string{"summary", row.Name, "", "", fmt.Sprint(row.Value), ""}); err != nil {
			return nil, err
		}
	}

	for _, item := range summary.Sponsors {
		rows := []struct {
			Name  string
			Count int
		}{
			{"pending_count", item.PendingCount},
			{"approved_count", item.ApprovedCount},
			{"rejected_count", item.RejectedCount},
			{"completed_count", item.CompletedCount},
			{"older_than_30_minutes_count", item.OlderThan30MinutesCount},
			{"older_than_4_hours_count", item.OlderThan4HoursCount},
			{"older_than_24_hours_count", item.OlderThan24HoursCount},
		}
		for _, row := range rows {
			if err := writer.Write([]string{"sponsor", row.Name, "", "", fmt.Sprint(row.Count), item.Name}); err != nil {
				return nil, err
			}
		}
		if err := writer.Write([]string{"sponsor", "avg_approval_minutes", "", "", fmt.Sprint(item.AvgApprovalMinutes), item.Name}); err != nil {
			return nil, err
		}
		if err := writer.Write([]string{"sponsor", "max_approval_minutes", "", "", fmt.Sprint(item.MaxApprovalMinutes), item.Name}); err != nil {
			return nil, err
		}
	}

	for _, item := range summary.Companies {
		if err := writer.Write([]string{"company", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
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
			{"pending_older_than_30_minutes_count", bucket.PendingOlderThan30MinutesCount},
			{"pending_older_than_4_hours_count", bucket.PendingOlderThan4HoursCount},
			{"pending_older_than_24_hours_count", bucket.PendingOlderThan24HoursCount},
			{"approved_count", bucket.ApprovedCount},
			{"rejected_count", bucket.RejectedCount},
			{"completed_count", bucket.CompletedCount},
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
