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

func HandleListAuditHistory(w http.ResponseWriter, r *http.Request) {
	userFilter := strings.TrimSpace(r.URL.Query().Get("user"))
	actionPrefix := strings.TrimSpace(r.URL.Query().Get("action_prefix"))
	limit := parseIntegrationHistoryLimit(r.URL.Query().Get("limit"), 200)

	history, err := db.ListAuditHistory(userFilter, actionPrefix, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats, err := db.GetAuditHistoryStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":  time.Now().UTC().Format(time.RFC3339),
		"user":          userFilter,
		"action_prefix": actionPrefix,
		"history":       history,
		"count":         len(history),
		"stats":         stats,
	})
}

func HandleExportAuditHistory(w http.ResponseWriter, r *http.Request) {
	userFilter := strings.TrimSpace(r.URL.Query().Get("user"))
	actionPrefix := strings.TrimSpace(r.URL.Query().Get("action_prefix"))
	history, err := db.ListAuditHistory(userFilter, actionPrefix, 5000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	filenamePrefix := "aegisnas-audit-history"
	if actionPrefix != "" {
		filenamePrefix += "-" + sanitizeDownloadName(actionPrefix)
	}

	switch format {
	case "", "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		writer := csv.NewWriter(w)
		defer writer.Flush()
		_ = writer.Write([]string{"id", "timestamp", "user", "action", "details", "result", "ip_address"})
		for _, item := range history {
			_ = writer.Write([]string{
				fmt.Sprint(item.ID),
				item.Timestamp,
				item.User,
				item.Action,
				item.Details,
				item.Result,
				item.IPAddress,
			})
		}
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filenamePrefix))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"generated_at":  time.Now().UTC().Format(time.RFC3339),
			"user":          userFilter,
			"action_prefix": actionPrefix,
			"history":       history,
			"count":         len(history),
		})
	default:
		http.Error(w, "unsupported export format", http.StatusBadRequest)
	}
}
