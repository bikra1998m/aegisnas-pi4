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

func HandleGetGuestRejectionAnalytics(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestRejectionAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, guestRejectionAnalyticsPayload(query, summary))
}

func HandleExportGuestRejectionAnalytics(w http.ResponseWriter, r *http.Request) {
	query := guestLifecycleQueryFromRequest(r, defaultGuestLifecycleLimit)
	summary, err := db.GetGuestRejectionAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	filenamePrefix := "aegisnas-guest-rejection-analytics"
	if query.Status != "" {
		filenamePrefix += "-" + sanitizeDownloadName(query.Status)
	}
	filenamePrefix += fmt.Sprintf("-%dh", summary.WindowHours)

	switch format {
	case "", "csv":
		payload, err := guestRejectionAnalyticsCSV(summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(guestRejectionAnalyticsPayload(query, summary))
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
	audit(r, "download_guest_rejection_analytics", filenamePrefix, "downloaded")
}

func guestRejectionAnalyticsPayload(query db.GuestLifecycleQuery, summary db.GuestRejectionAnalyticsSummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"status":       query.Status,
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"summary":      summary,
	}
}

func guestRejectionAnalyticsCSV(summary db.GuestRejectionAnalyticsSummary) ([]byte, error) {
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
		{"rejected_count", int64(summary.RejectedCount)},
		{"rejected_with_sponsor_count", int64(summary.RejectedWithSponsorCount)},
		{"rejected_without_sponsor_count", int64(summary.RejectedWithoutSponsorCount)},
		{"rejected_after_approval_count", int64(summary.RejectedAfterApprovalCount)},
		{"rejected_before_approval_count", int64(summary.RejectedBeforeApprovalCount)},
		{"unique_rejection_reasons_window", int64(summary.UniqueRejectionReasonsWindow)},
		{"unique_sponsors_window", int64(summary.UniqueSponsorsWindow)},
		{"unique_companies_window", int64(summary.UniqueCompaniesWindow)},
		{"avg_submit_to_rejection_minutes", summary.AvgSubmitToRejectionMinutes},
		{"max_submit_to_rejection_minutes", summary.MaxSubmitToRejectionMinutes},
	}
	for _, row := range summaryRows {
		if err := writer.Write([]string{"summary", row.Name, "", "", fmt.Sprint(row.Count), ""}); err != nil {
			return nil, err
		}
	}

	for _, item := range summary.RejectionReasons {
		if err := writer.Write([]string{"reason", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.Sponsors {
		if err := writer.Write([]string{"sponsor", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.Companies {
		if err := writer.Write([]string{"company", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.Roles {
		if err := writer.Write([]string{"role", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
			return nil, err
		}
	}
	for _, bucket := range summary.Buckets {
		rows := []struct {
			Name  string
			Count int
		}{
			{"rejected_count", bucket.RejectedCount},
			{"rejected_with_sponsor_count", bucket.RejectedWithSponsorCount},
			{"rejected_without_sponsor_count", bucket.RejectedWithoutSponsorCount},
			{"rejected_after_approval_count", bucket.RejectedAfterApprovalCount},
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
