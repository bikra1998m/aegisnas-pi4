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

func HandleGetVoucherExpiryAnalytics(w http.ResponseWriter, r *http.Request) {
	query := voucherExpiryAnalyticsQueryFromRequest(r)
	summary, err := db.GetVoucherExpiryAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, voucherExpiryAnalyticsPayload(summary))
}

func HandleExportVoucherExpiryAnalytics(w http.ResponseWriter, r *http.Request) {
	query := voucherExpiryAnalyticsQueryFromRequest(r)
	summary, err := db.GetVoucherExpiryAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	filenamePrefix := fmt.Sprintf("aegisnas-voucher-expiry-analytics-%dh", summary.WindowHours)
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "", "csv":
		payload, err := voucherExpiryAnalyticsCSV(summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(voucherExpiryAnalyticsPayload(summary))
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
	audit(r, "download_voucher_expiry_analytics", filenamePrefix, "downloaded")
}

func voucherExpiryAnalyticsQueryFromRequest(r *http.Request) db.VoucherExpiryQuery {
	windowHours := parsePositiveInt(r.URL.Query().Get("window_hours"), defaultVoucherAnalyticsWindowHours, 1, 24*365)
	bucketCount := parsePositiveInt(r.URL.Query().Get("bucket_count"), defaultVoucherAnalyticsBucketCount, 1, 90)
	return db.VoucherExpiryQuery{
		Window:      time.Duration(windowHours) * time.Hour,
		BucketCount: bucketCount,
	}
}

func voucherExpiryAnalyticsPayload(summary db.VoucherExpirySummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"summary":      summary,
	}
}

func voucherExpiryAnalyticsCSV(summary db.VoucherExpirySummary) ([]byte, error) {
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
		{"active_with_expiry_count", fmt.Sprint(summary.ActiveWithExpiryCount)},
		{"no_expiry_count", fmt.Sprint(summary.NoExpiryCount)},
		{"expired_count", fmt.Sprint(summary.ExpiredCount)},
		{"expired_unused_count", fmt.Sprint(summary.ExpiredUnusedCount)},
		{"expired_used_count", fmt.Sprint(summary.ExpiredUsedCount)},
		{"expiring_24_hours_count", fmt.Sprint(summary.Expiring24HoursCount)},
		{"expiring_7_days_count", fmt.Sprint(summary.Expiring7DaysCount)},
		{"expiring_in_window_count", fmt.Sprint(summary.ExpiringInWindowCount)},
		{"unused_expiring_in_window_count", fmt.Sprint(summary.UnusedExpiringInWindowCount)},
		{"active_expiring_in_window_count", fmt.Sprint(summary.ActiveExpiringInWindowCount)},
		{"exhausted_expiring_in_window_count", fmt.Sprint(summary.ExhaustedExpiringInWindowCount)},
		{"total_remaining_uses_expiring_in_window", fmt.Sprint(summary.TotalRemainingUsesExpiringInWindow)},
		{"avg_hours_until_expiry", fmt.Sprint(summary.AvgHoursUntilExpiry)},
		{"max_hours_until_expiry", fmt.Sprint(summary.MaxHoursUntilExpiry)},
		{"avg_expired_hours_ago", fmt.Sprint(summary.AvgExpiredHoursAgo)},
		{"max_expired_hours_ago", fmt.Sprint(summary.MaxExpiredHoursAgo)},
		{"soonest_expiry_at", summary.SoonestExpiryAt},
		{"latest_expiry_in_window_at", summary.LatestExpiryInWindowAt},
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
	for _, item := range summary.UnusedRoles {
		if err := writer.Write([]string{"unused_role", item.Name, "", "", fmt.Sprint(item.Count), ""}); err != nil {
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
			Count int64
		}{
			{"expiring_count", int64(bucket.ExpiringCount)},
			{"unused_expiring_count", int64(bucket.UnusedExpiringCount)},
			{"active_expiring_count", int64(bucket.ActiveExpiringCount)},
			{"exhausted_expiring_count", int64(bucket.ExhaustedExpiringCount)},
			{"remaining_uses", bucket.RemainingUses},
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
