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

const (
	defaultVoucherAnalyticsWindowHours = 30 * 24
	defaultVoucherAnalyticsBucketCount = 30
)

func HandleGetVoucherAnalytics(w http.ResponseWriter, r *http.Request) {
	query := voucherAnalyticsQueryFromRequest(r)
	summary, err := db.GetVoucherAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, voucherAnalyticsPayload(summary))
}

func HandleExportVoucherAnalytics(w http.ResponseWriter, r *http.Request) {
	query := voucherAnalyticsQueryFromRequest(r)
	summary, err := db.GetVoucherAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	filenamePrefix := fmt.Sprintf("aegisnas-voucher-analytics-%dh", summary.WindowHours)
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "", "csv":
		payload, err := voucherAnalyticsCSV(summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(voucherAnalyticsPayload(summary))
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
	audit(r, "download_voucher_analytics", filenamePrefix, "downloaded")
}

func voucherAnalyticsQueryFromRequest(r *http.Request) db.VoucherAnalyticsQuery {
	windowHours := parsePositiveInt(r.URL.Query().Get("window_hours"), defaultVoucherAnalyticsWindowHours, 1, 24*365)
	bucketCount := parsePositiveInt(r.URL.Query().Get("bucket_count"), defaultVoucherAnalyticsBucketCount, 1, 90)
	return db.VoucherAnalyticsQuery{
		Window:      time.Duration(windowHours) * time.Hour,
		BucketCount: bucketCount,
	}
}

func voucherAnalyticsPayload(summary db.VoucherAnalyticsSummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"summary":      summary,
	}
}

func voucherAnalyticsCSV(summary db.VoucherAnalyticsSummary) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"section", "name", "bucket_start", "bucket_end", "count", "value"}); err != nil {
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
		{"created_in_window_count", fmt.Sprint(summary.CreatedInWindowCount)},
		{"active_count", fmt.Sprint(summary.ActiveCount)},
		{"exhausted_count", fmt.Sprint(summary.ExhaustedCount)},
		{"expired_count", fmt.Sprint(summary.ExpiredCount)},
		{"expired_unused_count", fmt.Sprint(summary.ExpiredUnusedCount)},
		{"unused_count", fmt.Sprint(summary.UnusedCount)},
		{"partially_used_count", fmt.Sprint(summary.PartiallyUsedCount)},
		{"fully_used_count", fmt.Sprint(summary.FullyUsedCount)},
		{"expiring_24_hours_count", fmt.Sprint(summary.Expiring24HoursCount)},
		{"expiring_7_days_count", fmt.Sprint(summary.Expiring7DaysCount)},
		{"total_issued_uses", fmt.Sprint(summary.TotalIssuedUses)},
		{"total_used_uses", fmt.Sprint(summary.TotalUsedUses)},
		{"active_remaining_uses", fmt.Sprint(summary.ActiveRemainingUses)},
		{"utilization_percent", fmt.Sprint(summary.UtilizationPercent)},
		{"avg_duration_minutes", fmt.Sprint(summary.AvgDurationMinutes)},
		{"max_duration_minutes", fmt.Sprint(summary.MaxDurationMinutes)},
		{"latest_created_at", summary.LatestCreatedAt},
	}
	for _, row := range summaryRows {
		if err := writer.Write([]string{"summary", row.Name, "", "", "", row.Value}); err != nil {
			return nil, err
		}
	}

	for _, item := range summary.Roles {
		if err := writer.Write([]string{"role", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.States {
		if err := writer.Write([]string{"state", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
			return nil, err
		}
	}
	for _, bucket := range summary.Buckets {
		rows := []struct {
			Name  string
			Count int
		}{
			{"created_count", bucket.CreatedCount},
			{"active_count", bucket.ActiveCount},
			{"exhausted_count", bucket.ExhaustedCount},
			{"expired_count", bucket.ExpiredCount},
			{"unused_count", bucket.UnusedCount},
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
