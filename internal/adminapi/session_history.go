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

func HandleListSessionHistory(w http.ResponseWriter, r *http.Request) {
	query := sessionHistoryQueryFromRequest(r, 200)
	history, err := db.ListSessionHistory(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats, err := db.GetSessionHistoryStats(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"username":     strings.TrimSpace(r.URL.Query().Get("username")),
		"auth_method":  strings.TrimSpace(r.URL.Query().Get("auth_method")),
		"active":       parseSessionHistoryActiveQueryValue(r.URL.Query().Get("active")),
		"history":      history,
		"count":        len(history),
		"stats":        stats,
	})
}

func HandleExportSessionHistory(w http.ResponseWriter, r *http.Request) {
	query := sessionHistoryQueryFromRequest(r, 5000)
	history, err := db.ListSessionHistory(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats, err := db.GetSessionHistoryStats(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	filenamePrefix := "aegisnas-session-history"
	if query.Username != "" {
		filenamePrefix += "-" + sanitizeDownloadName(query.Username)
	}
	if query.AuthMethod != "" {
		filenamePrefix += "-" + sanitizeDownloadName(query.AuthMethod)
	}
	if query.ActiveOnly != nil {
		if *query.ActiveOnly {
			filenamePrefix += "-active"
		} else {
			filenamePrefix += "-ended"
		}
	}

	switch format {
	case "", "csv":
		payload, err := sessionHistoryCSV(history)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := sessionHistoryJSONPayload(query, history, stats)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	default:
		http.Error(w, "unsupported export format", http.StatusBadRequest)
	}
}

func sessionHistoryCSV(history []db.SessionHistoryRecord) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{
		"id", "username", "mac", "ip", "auth_method", "identity_source", "vlan", "role", "bandwidth_profile",
		"filter_id", "radius_class", "session_timeout", "idle_timeout", "acct_session_time", "called_station_id",
		"nas_identifier", "radius_session_id", "start_time", "last_activity", "end_time", "stop_reason",
		"bytes_in", "bytes_out", "total_bytes",
	}); err != nil {
		return nil, err
	}
	for _, item := range history {
		if err := writer.Write([]string{
			item.ID,
			item.Username,
			item.MAC,
			item.IP,
			item.AuthMethod,
			item.IdentitySource,
			strconv.Itoa(item.VLAN),
			item.Role,
			item.BandwidthProfile,
			item.FilterID,
			item.RadiusClass,
			strconv.Itoa(item.SessionTimeout),
			strconv.Itoa(item.IdleTimeout),
			fmt.Sprint(item.AcctSessionTime),
			item.CalledStationID,
			item.NASIdentifier,
			item.RadiusSessionID,
			item.StartTime,
			item.LastActivity,
			item.EndTime,
			item.StopReason,
			fmt.Sprint(item.BytesIn),
			fmt.Sprint(item.BytesOut),
			fmt.Sprint(item.TotalBytes),
		}); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func sessionHistoryJSONPayload(query db.SessionHistoryQuery, history []db.SessionHistoryRecord, stats db.SessionHistoryStats) ([]byte, error) {
	data, err := jsonMarshalIndented(map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"username":     query.Username,
		"auth_method":  query.AuthMethod,
		"active":       sessionHistoryActiveValue(query.ActiveOnly),
		"history":      history,
		"count":        len(history),
		"stats":        stats,
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func sessionHistoryQueryFromRequest(r *http.Request, fallbackLimit int) db.SessionHistoryQuery {
	return db.SessionHistoryQuery{
		Username:     strings.TrimSpace(r.URL.Query().Get("username")),
		AuthMethod:   strings.TrimSpace(r.URL.Query().Get("auth_method")),
		ActiveOnly:   parseSessionHistoryActiveQueryValue(r.URL.Query().Get("active")),
		TenantScopes: adminTenantScopesFromRequest(r),
		Limit:        parseSessionHistoryLimit(r.URL.Query().Get("limit"), fallbackLimit),
	}
}

func parseSessionHistoryLimit(raw string, fallback int) int {
	if fallback <= 0 {
		fallback = 100
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	if value > 5000 {
		return 5000
	}
	return value
}

func parseSessionHistoryActiveQueryValue(raw string) *bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes":
		value := true
		return &value
	case "false", "0", "no":
		value := false
		return &value
	default:
		return nil
	}
}

func sessionHistoryActiveValue(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}
