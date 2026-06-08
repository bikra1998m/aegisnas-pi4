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

func HandleGetVoucherAgingAnalytics(w http.ResponseWriter, r *http.Request) {
	query := voucherAgingAnalyticsQueryFromRequest(r)
	summary, err := db.GetVoucherAgingAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, voucherAgingAnalyticsPayload(summary))
}

func HandleExportVoucherAgingAnalytics(w http.ResponseWriter, r *http.Request) {
	query := voucherAgingAnalyticsQueryFromRequest(r)
	summary, err := db.GetVoucherAgingAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	filenamePrefix := fmt.Sprintf("aegisnas-voucher-aging-analytics-%dh", summary.WindowHours)
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "", "csv":
		payload, err := voucherAgingAnalyticsCSV(summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(voucherAgingAnalyticsPayload(summary))
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
	audit(r, "download_voucher_aging_analytics", filenamePrefix, "downloaded")
}

func voucherAgingAnalyticsQueryFromRequest(r *http.Request) db.VoucherAgingQuery {
	windowHours := parsePositiveInt(r.URL.Query().Get("window_hours"), defaultVoucherAnalyticsWindowHours, 1, 24*365)
	bucketCount := parsePositiveInt(r.URL.Query().Get("bucket_count"), defaultVoucherAnalyticsBucketCount, 1, 90)
	return db.VoucherAgingQuery{
		Window:      time.Duration(windowHours) * time.Hour,
		BucketCount: bucketCount,
	}
}

func voucherAgingAnalyticsPayload(summary db.VoucherAgingSummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"summary":      summary,
	}
}

func voucherAgingAnalyticsCSV(summary db.VoucherAgingSummary) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"section", "name", "bucket_min_age_minutes", "bucket_max_age_minutes", "count", "value"}); err != nil {
		return nil, err
	}

	summaryRows := []struct {
		Name  string
		Value string
	}{
		{"window_hours", fmt.Sprint(summary.WindowHours)},
		{"bucket_count", fmt.Sprint(summary.BucketCount)},
		{"bucket_minutes", fmt.Sprint(summary.BucketMinutes)},
		{"total_vouchers", fmt.Sprint(summary.TotalVouchers)},
		{"within_window_count", fmt.Sprint(summary.WithinWindowCount)},
		{"older_than_window_count", fmt.Sprint(summary.OlderThanWindowCount)},
		{"unused_within_window_count", fmt.Sprint(summary.UnusedWithinWindowCount)},
		{"unused_older_than_window_count", fmt.Sprint(summary.UnusedOlderThanWindowCount)},
		{"active_older_than_window_count", fmt.Sprint(summary.ActiveOlderThanWindowCount)},
		{"exhausted_older_than_window_count", fmt.Sprint(summary.ExhaustedOlderThanWindowCount)},
		{"expired_older_than_window_count", fmt.Sprint(summary.ExpiredOlderThanWindowCount)},
		{"remaining_uses_older_than_window", fmt.Sprint(summary.RemainingUsesOlderThanWindow)},
		{"unused_older_24_hours_count", fmt.Sprint(summary.UnusedOlder24HoursCount)},
		{"unused_older_7_days_count", fmt.Sprint(summary.UnusedOlder7DaysCount)},
		{"unused_older_30_days_count", fmt.Sprint(summary.UnusedOlder30DaysCount)},
		{"avg_age_minutes", fmt.Sprint(summary.AvgAgeMinutes)},
		{"max_age_minutes", fmt.Sprint(summary.MaxAgeMinutes)},
		{"avg_unused_age_minutes", fmt.Sprint(summary.AvgUnusedAgeMinutes)},
		{"max_unused_age_minutes", fmt.Sprint(summary.MaxUnusedAgeMinutes)},
		{"newest_created_at", summary.NewestCreatedAt},
		{"oldest_created_at", summary.OldestCreatedAt},
		{"oldest_unused_created_at", summary.OldestUnusedCreatedAt},
	}
	for _, row := range summaryRows {
		if err := writer.Write([]string{"summary", row.Name, "", "", "", row.Value}); err != nil {
			return nil, err
		}
	}

	for _, item := range summary.OlderRoles {
		if err := writer.Write([]string{"older_role", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.UnusedOlderRoles {
		if err := writer.Write([]string{"unused_older_role", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
			return nil, err
		}
	}
	for _, bucket := range summary.Buckets {
		rows := []struct {
			Name  string
			Count int64
		}{
			{"voucher_count", int64(bucket.VoucherCount)},
			{"unused_count", int64(bucket.UnusedCount)},
			{"active_count", int64(bucket.ActiveCount)},
			{"exhausted_count", int64(bucket.ExhaustedCount)},
			{"expired_count", int64(bucket.ExpiredCount)},
			{"remaining_uses", bucket.RemainingUses},
		}
		for _, row := range rows {
			if err := writer.Write([]string{
				"bucket",
				row.Name,
				fmt.Sprint(bucket.MinAgeMinutes),
				fmt.Sprint(bucket.MaxAgeMinutes),
				fmt.Sprint(row.Count),
				"",
			}); err != nil {
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
