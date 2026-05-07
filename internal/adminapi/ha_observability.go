package adminapi

import (
	"encoding/csv"
	"encoding/json"
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
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-ha-history.csv"`)
		writer := csv.NewWriter(w)
		defer writer.Flush()
		_ = writer.Write([]string{"id", "created_at", "event_type", "status", "summary", "node_role", "actor", "details_json"})
		for _, item := range history {
			_ = writer.Write([]string{
				fmt.Sprint(item.ID),
				item.CreatedAt,
				item.EventType,
				item.Status,
				item.Summary,
				item.NodeRole,
				item.Actor,
				string(item.Details),
			})
		}
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-ha-history.json"`)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"history":      history,
			"count":        len(history),
		})
	default:
		http.Error(w, "unsupported export format", http.StatusBadRequest)
	}
}
