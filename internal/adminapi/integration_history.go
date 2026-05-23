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

func HandleListIntegrationHistory(w http.ResponseWriter, r *http.Request) {
	component := strings.TrimSpace(r.URL.Query().Get("component"))
	limit := parseIntegrationHistoryLimit(r.URL.Query().Get("limit"), 200)

	history, err := db.ListIntegrationHistory(component, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats, err := db.GetIntegrationHistoryStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"component":    component,
		"history":      history,
		"count":        len(history),
		"stats":        stats,
	})
}

func HandleExportIntegrationHistory(w http.ResponseWriter, r *http.Request) {
	component := strings.TrimSpace(r.URL.Query().Get("component"))
	history, err := db.ListIntegrationHistory(component, 2000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	filenamePrefix := "aegisnas-integration-history"
	if component != "" {
		filenamePrefix += "-" + sanitizeDownloadName(component)
	}

	switch format {
	case "", "csv":
		payload, err := integrationHistoryCSV(history)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := integrationHistoryJSONPayload(component, history)
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

func integrationHistoryCSV(history []db.IntegrationHistoryRecord) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"id", "created_at", "component", "status", "summary", "details_json"}); err != nil {
		return nil, err
	}
	for _, item := range history {
		if err := writer.Write([]string{
			fmt.Sprint(item.ID),
			item.CreatedAt,
			item.Component,
			item.Status,
			item.Summary,
			string(item.Details),
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

func integrationHistoryJSONPayload(component string, history []db.IntegrationHistoryRecord) ([]byte, error) {
	data, err := jsonMarshalIndented(map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"component":    component,
		"history":      history,
		"count":        len(history),
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func parseIntegrationHistoryLimit(raw string, fallback int) int {
	if fallback <= 0 {
		fallback = 100
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	if value > 2000 {
		return 2000
	}
	return value
}

func sanitizeDownloadName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-", ".", "-", ",", "-", "__", "_")
	value = replacer.Replace(value)
	value = strings.Trim(value, "-_")
	if value == "" {
		return "history"
	}
	return value
}
