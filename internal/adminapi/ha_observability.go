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

func HandleListHAHistory(w http.ResponseWriter, r *http.Request) {
	history, err := db.ListHAHistory(200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats, err := db.GetHAHistoryStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"history":      history,
		"count":        len(history),
		"stats":        stats,
	})
}

func HandleExportHAHistory(w http.ResponseWriter, r *http.Request) {
	history, err := db.ListHAHistory(2000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch format {
	case "", "csv":
		payload, err := haHistoryCSV(history)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-ha-history.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := haHistoryJSONPayload(history)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-ha-history.json"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	default:
		http.Error(w, "unsupported export format", http.StatusBadRequest)
	}
}

func haHistoryCSV(history []db.HAHistoryRecord) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"id", "created_at", "event_type", "status", "summary", "node_role", "actor", "details_json"}); err != nil {
		return nil, err
	}
	for _, item := range history {
		if err := writer.Write([]string{
			fmt.Sprint(item.ID),
			item.CreatedAt,
			item.EventType,
			item.Status,
			item.Summary,
			item.NodeRole,
			item.Actor,
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

func haHistoryJSONPayload(history []db.HAHistoryRecord) ([]byte, error) {
	data, err := jsonMarshalIndented(map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"history":      history,
		"count":        len(history),
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
