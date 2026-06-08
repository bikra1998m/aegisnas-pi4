package adminapi

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func HandleGetVoucherRedemptionAnalytics(w http.ResponseWriter, r *http.Request) {
	query := voucherRedemptionAnalyticsQueryFromRequest(r)
	summary, err := db.GetVoucherRedemptionAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, voucherRedemptionAnalyticsPayload(summary))
}

func HandleExportVoucherRedemptionAnalytics(w http.ResponseWriter, r *http.Request) {
	query := voucherRedemptionAnalyticsQueryFromRequest(r)
	summary, err := db.GetVoucherRedemptionAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	filenamePrefix := fmt.Sprintf("aegisnas-voucher-redemption-analytics-%dh", summary.WindowHours)
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "", "csv":
		payload, err := voucherRedemptionAnalyticsCSV(summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(voucherRedemptionAnalyticsPayload(summary))
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
	audit(r, "download_voucher_redemption_analytics", filenamePrefix, "downloaded")
}

func voucherRedemptionAnalyticsQueryFromRequest(r *http.Request) db.VoucherRedemptionQuery {
	windowHours := parsePositiveInt(r.URL.Query().Get("window_hours"), defaultVoucherAnalyticsWindowHours, 1, 24*365)
	bucketCount := parsePositiveInt(r.URL.Query().Get("bucket_count"), defaultVoucherAnalyticsBucketCount, 1, 90)
	return db.VoucherRedemptionQuery{
		Window:      time.Duration(windowHours) * time.Hour,
		BucketCount: bucketCount,
	}
}

func voucherRedemptionAnalyticsPayload(summary db.VoucherRedemptionSummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"summary":      summary,
	}
}

func voucherRedemptionAnalyticsCSV(summary db.VoucherRedemptionSummary) ([]byte, error) {
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
		{"redeemed_voucher_count", fmt.Sprint(summary.RedeemedVoucherCount)},
		{"never_redeemed_count", fmt.Sprint(summary.NeverRedeemedCount)},
		{"redeemed_in_window_count", fmt.Sprint(summary.RedeemedInWindowCount)},
		{"first_redeemed_in_window_count", fmt.Sprint(summary.FirstRedeemedInWindowCount)},
		{"redeemed_once_count", fmt.Sprint(summary.RedeemedOnceCount)},
		{"redeemed_repeat_count", fmt.Sprint(summary.RedeemedRepeatCount)},
		{"session_start_count", fmt.Sprint(summary.SessionStartCount)},
		{"ended_session_count", fmt.Sprint(summary.EndedSessionCount)},
		{"active_session_count", fmt.Sprint(summary.ActiveSessionCount)},
		{"active_voucher_count", fmt.Sprint(summary.ActiveVoucherCount)},
		{"redeemed_within_24_hours_count", fmt.Sprint(summary.RedeemedWithin24HoursCount)},
		{"redeemed_within_7_days_count", fmt.Sprint(summary.RedeemedWithin7DaysCount)},
		{"avg_sessions_per_redeemed_voucher", strconv.FormatFloat(summary.AvgSessionsPerRedeemedVoucher, 'f', 2, 64)},
		{"avg_first_redemption_delay_minutes", fmt.Sprint(summary.AvgFirstRedemptionDelayMinutes)},
		{"max_first_redemption_delay_minutes", fmt.Sprint(summary.MaxFirstRedemptionDelayMinutes)},
		{"ended_traffic_total", fmt.Sprint(summary.EndedTrafficTotal)},
		{"avg_ended_session_seconds", fmt.Sprint(summary.AvgEndedSessionSeconds)},
		{"max_ended_session_seconds", fmt.Sprint(summary.MaxEndedSessionSeconds)},
		{"latest_session_start_at", summary.LatestSessionStartAt},
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
	for _, bucket := range summary.Buckets {
		rows := []struct {
			Name  string
			Count int64
		}{
			{"session_start_count", int64(bucket.SessionStartCount)},
			{"unique_voucher_count", int64(bucket.UniqueVoucherCount)},
			{"first_redeemed_count", int64(bucket.FirstRedeemedCount)},
			{"ended_count", int64(bucket.EndedCount)},
			{"ended_traffic_total", bucket.EndedTrafficTotal},
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
