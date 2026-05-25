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

const (
	defaultSessionAnalyticsWindowHours = 24
	defaultSessionAnalyticsBucketCount = 24
)

func HandleGetSessionAnalytics(w http.ResponseWriter, r *http.Request) {
	query := sessionAnalyticsQueryFromRequest(r)
	summary, err := db.GetSessionAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, sessionAnalyticsPayload(query, summary))
}

func HandleExportSessionAnalytics(w http.ResponseWriter, r *http.Request) {
	query := sessionAnalyticsQueryFromRequest(r)
	summary, err := db.GetSessionAnalytics(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	filenamePrefix := "aegisnas-session-analytics"
	if query.Username != "" {
		filenamePrefix += "-" + sanitizeDownloadName(query.Username)
	}
	if query.AuthMethod != "" {
		filenamePrefix += "-" + sanitizeDownloadName(query.AuthMethod)
	}
	filenamePrefix += fmt.Sprintf("-%dh", summary.WindowHours)

	switch format {
	case "", "csv":
		payload, err := sessionAnalyticsCSV(summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := jsonMarshalIndented(sessionAnalyticsPayload(query, summary))
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

func sessionAnalyticsQueryFromRequest(r *http.Request) db.SessionAnalyticsQuery {
	windowHours := parsePositiveInt(r.URL.Query().Get("window_hours"), defaultSessionAnalyticsWindowHours, 1, 168)
	bucketCount := parsePositiveInt(r.URL.Query().Get("bucket_count"), defaultSessionAnalyticsBucketCount, 1, 96)
	return db.SessionAnalyticsQuery{
		Username:     strings.TrimSpace(r.URL.Query().Get("username")),
		AuthMethod:   strings.TrimSpace(r.URL.Query().Get("auth_method")),
		TenantScopes: adminTenantScopesFromRequest(r),
		Window:       time.Duration(windowHours) * time.Hour,
		BucketCount:  bucketCount,
	}
}

func sessionAnalyticsPayload(query db.SessionAnalyticsQuery, summary db.SessionAnalyticsSummary) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"username":     query.Username,
		"auth_method":  query.AuthMethod,
		"window_hours": summary.WindowHours,
		"bucket_count": summary.BucketCount,
		"summary":      summary,
	}
}

func sessionAnalyticsCSV(summary db.SessionAnalyticsSummary) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"section", "name", "bucket_start", "bucket_end", "count", "bytes_total", "seconds_total"}); err != nil {
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
		{"started_count", int64(summary.StartedCount)},
		{"ended_count", int64(summary.EndedCount)},
		{"active_now", int64(summary.ActiveNow)},
		{"unique_users_window", int64(summary.UniqueUsersWindow)},
		{"unique_macs_window", int64(summary.UniqueMACsWindow)},
		{"unique_ips_window", int64(summary.UniqueIPsWindow)},
		{"avg_ended_session_seconds", summary.AvgEndedSessionSeconds},
		{"max_ended_session_seconds", summary.MaxEndedSessionSeconds},
		{"longest_active_session_seconds", summary.LongestActiveSessionSeconds},
		{"peak_concurrent_sessions", int64(summary.PeakConcurrentSessions)},
	}
	for _, row := range summaryRows {
		if err := writer.Write([]string{"summary", row.Name, "", "", fmt.Sprint(row.Count), "", ""}); err != nil {
			return nil, err
		}
	}
	if err := writer.Write([]string{"summary", "ended_traffic_total", "", "", "", fmt.Sprint(summary.EndedTrafficTotal), ""}); err != nil {
		return nil, err
	}
	if err := writer.Write([]string{"summary", "ended_session_seconds_total", "", "", "", "", fmt.Sprint(summary.EndedSessionSecondsTotal)}); err != nil {
		return nil, err
	}

	for _, item := range summary.AuthMethods {
		if err := writer.Write([]string{"auth_method", item.Name, "", "", fmt.Sprint(item.Count), "", ""}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.Roles {
		if err := writer.Write([]string{"role", item.Name, "", "", fmt.Sprint(item.Count), "", ""}); err != nil {
			return nil, err
		}
	}
	for _, item := range summary.VLANs {
		if err := writer.Write([]string{"vlan", item.Name, "", "", fmt.Sprint(item.Count), "", ""}); err != nil {
			return nil, err
		}
	}
	for _, bucket := range summary.Buckets {
		if err := writer.Write([]string{"bucket", "started_count", bucket.Start, bucket.End, fmt.Sprint(bucket.StartedCount), "", ""}); err != nil {
			return nil, err
		}
		if err := writer.Write([]string{"bucket", "ended_count", bucket.Start, bucket.End, fmt.Sprint(bucket.EndedCount), "", ""}); err != nil {
			return nil, err
		}
		if err := writer.Write([]string{"bucket", "ended_traffic_total", bucket.Start, bucket.End, "", fmt.Sprint(bucket.EndedTrafficTotal), ""}); err != nil {
			return nil, err
		}
		if err := writer.Write([]string{"bucket", "ended_session_seconds_total", bucket.Start, bucket.End, "", "", fmt.Sprint(bucket.EndedSessionSecondsTotal)}); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func parsePositiveInt(raw string, fallback, minValue, maxValue int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		value = fallback
	}
	if value < minValue {
		value = minValue
	}
	if value > maxValue {
		value = maxValue
	}
	return value
}
